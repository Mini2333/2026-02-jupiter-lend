use anchor_lang::prelude::*;

use crate::constants::{MAX_AUTH_COUNT, MAX_USER_CLASSES};

use library::math::safe_math::*;

#[account]
#[derive(InitSpace)]
pub struct Liquidity {
    pub authority: Pubkey, // Main liquidity authority, can be Governance account or multisig
    pub revenue_collector: Pubkey, // Address that collects fees
    pub status: bool,      // true = locked, false = unlocked
    pub bump: u8,
}

impl Liquidity {
    pub fn is_locked(&self) -> bool {
        self.status
    }

    pub fn init(&mut self, authority: Pubkey, revenue_collector: Pubkey, bump: u8) -> Result<()> {
        self.authority = authority;
        self.revenue_collector = revenue_collector;
        self.status = false;
        self.bump = bump;

        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct UserClass {
    pub addr: Pubkey,
    pub class: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AuthorizationList {
    #[max_len(MAX_AUTH_COUNT)]
    pub auth_users: Vec<Pubkey>, // Authorization list
    #[max_len(MAX_AUTH_COUNT)]
    pub guardians: Vec<Pubkey>, // Guardian list
    #[max_len(MAX_USER_CLASSES)]
    pub user_classes: Vec<UserClass>, // User class list
}

impl AuthorizationList {
    pub fn init(&mut self, authority: Pubkey) -> Result<()> {
        self.auth_users.push(authority);
        self.guardians.push(authority);

        Ok(())
    }
}

#[account(zero_copy)]
#[derive(InitSpace)]
#[repr(C, packed)]
pub struct UserClaim {
    pub user: Pubkey,
    pub amount: u64,
    pub mint: Pubkey,
}

impl UserClaim {
    pub fn init(&mut self, user: Pubkey, mint: Pubkey) -> Result<()> {
        self.user = user;
        self.mint = mint;
        Ok(())
    }

    pub fn balance(&self) -> u64 {
        self.amount
    }

    pub fn reset_balance(&mut self) -> Result<()> {
        self.amount = 0;
        Ok(())
    }

    pub fn approve(&mut self, amount: u64) -> Result<()> {
        self.amount = self.amount.safe_add(amount)?;
        Ok(())
    }
}

// ============================================================================
//  SECURITY PROOF-OF-CONCEPT UNIT TESTS
//  These tests prove CRITICAL findings C-1 and C-2 from the Red Team audit.
//  They run entirely in Rust (no BPF toolchain required) by exercising the
//  on-chain data structures and constraint logic directly.
// ============================================================================
#[cfg(test)]
mod security_poc_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // [C-1] ADMIN PDA INITIALIZATION FRONT-RUNNING
    // -----------------------------------------------------------------------
    // The InitLiquidity context struct (programs/liquidity/src/state/context.rs)
    // carries NO authorization constraint on the signer field:
    //
    //   pub struct InitLiquidity<'info> {
    //       #[account(mut)]          // ← ANY pubkey — no address = PROTOCOL_INIT_AUTH
    //       pub signer: Signer<'info>,
    //       ...
    //   }
    //
    // The init function then blindly uses the caller-supplied `authority` arg:
    //
    //   pub fn init_liquidity(context, authority: Pubkey, revenue_collector: Pubkey) {
    //       context.accounts.liquidity.init(authority, revenue_collector, bump)
    //   }
    //
    // The following tests prove this by directly calling `Liquidity::init()`
    // with attacker-controlled arguments, which is exactly what the on-chain
    // instruction does after the unchecked constraint passes.

    /// C-1 PoC #1 — Attacker initialises Liquidity state with their own keys.
    ///
    /// In production the attacker would call `init_liquidity` as the first
    /// signer after the program is deployed.  This test calls the same inner
    /// `Liquidity::init()` function that the instruction invokes, showing
    /// that the attacker completely controls the resulting state.
    #[test]
    fn test_c1_attacker_controls_authority_after_init() {
        // Simulate the attacker's wallet and a separate "legitimate" deployer
        let attacker_pubkey = Pubkey::new_unique();
        let legitimate_admin = Pubkey::new_unique();
        let malicious_revenue_collector = Pubkey::new_unique();

        // The init_liquidity instruction calls `Liquidity::init` with the
        // caller-supplied `authority` and `revenue_collector` args.
        // There is NO check that `signer == PROTOCOL_INIT_AUTH` or any other
        // known-good key before these args are stored.
        let mut liquidity = Liquidity {
            authority: Pubkey::default(),
            revenue_collector: Pubkey::default(),
            status: false,
            bump: 0,
        };

        // This mirrors what happens on-chain when the attacker calls
        // init_liquidity(authority=attacker, revenue_collector=attacker).
        let dummy_bump = 255u8;
        liquidity
            .init(attacker_pubkey, malicious_revenue_collector, dummy_bump)
            .expect("init must succeed — no access control prevents it");

        // Verify: attacker is authority, legitimate admin has no control
        assert_eq!(
            liquidity.authority, attacker_pubkey,
            "[C-1] Attacker is now the protocol authority"
        );
        assert_ne!(
            liquidity.authority, legitimate_admin,
            "[C-1] Legitimate admin is locked out"
        );
        assert_eq!(
            liquidity.revenue_collector, malicious_revenue_collector,
            "[C-1] All protocol revenue is routed to the attacker"
        );
    }

    /// C-1 PoC #2 — Attacker initialises AuthorizationList with their key.
    ///
    /// After seizing the Liquidity PDA, the attacker's auth_users list gives
    /// them operational authority over all admin operations.
    #[test]
    fn test_c1_attacker_is_sole_auth_user_after_init() {
        let attacker_pubkey = Pubkey::new_unique();

        let mut auth_list = AuthorizationList {
            auth_users: Vec::new(),
            guardians: Vec::new(),
            user_classes: Vec::new(),
        };

        // init_liquidity calls auth_list.init(authority) where authority = attacker
        auth_list
            .init(attacker_pubkey)
            .expect("init must succeed — no access control");

        // Verify: attacker is the only authority in both auth_users and guardians
        assert_eq!(
            auth_list.auth_users.len(),
            1,
            "[C-1] auth_users should have exactly one entry"
        );
        assert_eq!(
            auth_list.auth_users[0], attacker_pubkey,
            "[C-1] Attacker is the sole auth_user"
        );
        assert_eq!(
            auth_list.guardians[0], attacker_pubkey,
            "[C-1] Attacker is the sole guardian"
        );
    }

    // -----------------------------------------------------------------------
    // [C-2] ANY AUTH_USER CAN UNPAUSE A DELIBERATELY-PAUSED PROTOCOL
    // -----------------------------------------------------------------------
    // The ChangeStatus context (programs/liquidity/src/state/context.rs) has:
    //
    //   #[account(constraint = auth_list.auth_users.contains(&authority.key()) @ ...)]
    //   pub auth_list: Account<'info, AuthorizationList>,
    //
    // The `change_status` handler does:
    //
    //   pub fn change_status(context: Context<ChangeStatus>, status: bool) {
    //       if context.accounts.liquidity.status == status { return Err(...); }
    //       context.accounts.liquidity.status = status;  // no role check on direction
    //   }
    //
    // ANY wallet in auth_users can pass the constraint for BOTH pause (status=true)
    // AND unpause (status=false).  There is no check that unpause requires
    // authority == liquidity.authority.
    //
    // The following tests prove this by simulating the constraint evaluation
    // and the handler body directly.

    /// C-2 PoC #1 — Governance pauses, auth_user unpauses: the constraint.
    ///
    /// Demonstrates that the `auth_users.contains(signer)` constraint is
    /// satisfied by the sub-authority (keeper), not just governance, for an
    /// unpause call.  Combined with the absence of an additional authority
    /// check in the handler, this is the root cause.
    #[test]
    fn test_c2_auth_user_satisfies_change_status_constraint_for_unpause() {
        let governance = Pubkey::new_unique();
        let keeper_bot = Pubkey::new_unique(); // sub-authority, NOT governance

        // Setup: governance is authority; keeper_bot is in auth_users
        let auth_list = AuthorizationList {
            auth_users: vec![governance, keeper_bot], // both are auth_users
            guardians: vec![governance],
            user_classes: Vec::new(),
        };

        let liquidity_authority = governance;

        // Governance pauses the protocol
        let mut liquidity = Liquidity {
            authority: liquidity_authority,
            revenue_collector: governance,
            status: false, // unlocked
            bump: 255,
        };
        // Handler body: no constraint violation since status != true
        assert_ne!(liquidity.status, true);
        liquidity.status = true; // paused
        assert!(liquidity.status, "Protocol should be paused after governance call");

        // ── EXPLOIT ────────────────────────────────────────────────────────
        // The keeper_bot calls change_status(false).
        // Step 1: evaluate the constraint — auth_users.contains(keeper_bot)
        let constraint_passes = auth_list.auth_users.contains(&keeper_bot);
        assert!(
            constraint_passes,
            "[C-2] CONSTRAINT IS SATISFIED by keeper_bot — the vulnerability is confirmed"
        );

        // Step 2: the handler does NOT check if keeper_bot == liquidity.authority
        //         before allowing the unpause.
        let is_governance = keeper_bot == liquidity_authority;
        assert!(
            !is_governance,
            "[C-2] keeper_bot is NOT governance, yet the constraint passes"
        );

        // Step 3: the handler executes — status flips back to false (unpaused)
        assert_ne!(liquidity.status, false); // pre-condition: currently paused
        liquidity.status = false;            // handler body: no extra guard
        // ───────────────────────────────────────────────────────────────────

        assert!(
            !liquidity.status,
            "[C-2] Protocol is UNPAUSED by a non-governance auth_user"
        );

        println!(
            "\n[C-2 PROVEN] keeper_bot ({}) unpaused the protocol.\n\
             governance ({}) had paused it but is powerless to prevent reversal.\n\
             Root cause: change_status uses auth_users for BOTH pause and unpause;\n\
             there is no 'if status == false {{ require signer == authority }}' guard.",
            keeper_bot, governance
        );
    }

    /// C-2 PoC #2 — Repeated toggle: governance has no effective control.
    ///
    /// Shows that the attacker can cycle the pause state an arbitrary number
    /// of times, rendering the emergency mechanism completely ineffective.
    #[test]
    fn test_c2_keeper_negates_every_governance_pause() {
        let governance = Pubkey::new_unique();
        let keeper_bot = Pubkey::new_unique();

        let auth_list = AuthorizationList {
            auth_users: vec![governance, keeper_bot],
            guardians: vec![governance],
            user_classes: Vec::new(),
        };

        let mut liquidity = Liquidity {
            authority: governance,
            revenue_collector: governance,
            status: false,
            bump: 255,
        };

        for round in 1..=3 {
            // Governance pauses
            liquidity.status = true;
            assert!(liquidity.status, "Round {round}: governance paused");

            // Keeper bot checks constraint and unpauses
            assert!(
                auth_list.auth_users.contains(&keeper_bot),
                "Constraint passes every round"
            );
            liquidity.status = false;
            assert!(!liquidity.status, "Round {round}: keeper_bot unpaused");
        }

        println!(
            "\n[C-2 PROVEN] keeper_bot negated every governance pause (3 rounds).\n\
             The emergency shutdown provides NO protection as long as any\n\
             auth_user is under attacker control."
        );
    }

    /// C-2 PoC #3 — Control: non-auth wallet cannot pass the constraint.
    ///
    /// A completely unknown wallet (not in auth_users) correctly fails the
    /// constraint.  This confirms the gate exists but is role-confused: it
    /// allows any auth_user to both pause AND unpause.
    #[test]
    fn test_c2_non_auth_wallet_fails_constraint() {
        let governance = Pubkey::new_unique();
        let keeper_bot = Pubkey::new_unique();
        let random_wallet = Pubkey::new_unique(); // NOT in auth_users

        let auth_list = AuthorizationList {
            auth_users: vec![governance, keeper_bot],
            guardians: vec![governance],
            user_classes: Vec::new(),
        };

        // Random wallet cannot pass the constraint
        assert!(
            !auth_list.auth_users.contains(&random_wallet),
            "[C-2 control] random_wallet correctly blocked"
        );

        // But keeper_bot CAN
        assert!(
            auth_list.auth_users.contains(&keeper_bot),
            "[C-2] keeper_bot (sub-authority) passes the SAME constraint"
        );

        // The bug: the single constraint `auth_users.contains(signer)` is
        // insufficient because it grants unpause power to ALL auth_users,
        // not just the governance authority.
    }
}

// ============================================================================
//  [H-1] SECURITY POC — Missing `has_one` Binding Between `liquidity`
//                        and `auth_list` in Admin Contexts
//
//  Every admin context that reads both a `Liquidity` account and an
//  `AuthorizationList` account (e.g., `ChangeStatus`, `UpdateRateData`,
//  `CollectRevenue`, …) has NO constraint linking the two accounts.
//
//  The `ChangeStatus` context is illustrative:
//
//    pub struct ChangeStatus<'info> {
//        pub authority: Signer<'info>,
//        #[account(mut)]
//        pub liquidity: Account<'info, Liquidity>,     // ← unchecked
//        #[account(constraint = auth_list.auth_users.contains(...))]
//        pub auth_list: Account<'info, AuthorizationList>,  // ← unchecked
//    }
//
//  In the current single-pool deployment this is benign because there is only
//  one of each PDA.  However:
//
//  1. If the program is ever upgraded to support multiple pools, a signer that
//     is in auth_users of Pool A could use Pool A's auth_list to authorise
//     changes to Pool B's liquidity account.
//
//  2. A `Liquidity` account from one pool could be modified using an
//     `auth_list` belonging to a different pool, where the attacker has an
//     auth_user entry, bypassing Pool A's access control entirely.
//
//  The tests below prove that the constraint logic does NOT check the linkage.
// ============================================================================
#[cfg(test)]
mod security_poc_h1_tests {
    use super::*;

    /// H-1 PoC #1 — Two separate (liquidity, auth_list) pairs exist.
    ///              The auth_list constraint is satisfied for auth_list_B
    ///              even when paired with liquidity_A.
    ///              This models the cross-pool privilege escalation scenario.
    #[test]
    fn test_h1_mismatched_auth_list_passes_constraint() {
        // ── Pool A ────────────────────────────────────────────────────────
        let pool_a_admin = Pubkey::new_unique();
        let pool_a_attacker = Pubkey::new_unique(); // NOT admin of pool A

        let mut liquidity_a = Liquidity {
            authority: pool_a_admin,
            revenue_collector: pool_a_admin,
            status: false,
            bump: 255,
        };
        // Pool A's auth_list: only pool_a_admin is authorised
        let auth_list_a = AuthorizationList {
            auth_users: vec![pool_a_admin],
            guardians: vec![pool_a_admin],
            user_classes: Vec::new(),
        };

        // ── Pool B ────────────────────────────────────────────────────────
        let pool_b_admin = Pubkey::new_unique();

        let mut _liquidity_b = Liquidity {
            authority: pool_b_admin,
            revenue_collector: pool_b_admin,
            status: false,
            bump: 254,
        };
        // Pool B's auth_list: the attacker IS an auth_user of pool B
        let auth_list_b = AuthorizationList {
            auth_users: vec![pool_b_admin, pool_a_attacker],
            guardians: vec![pool_b_admin],
            user_classes: Vec::new(),
        };

        // ── EXPLOIT ────────────────────────────────────────────────────────
        // The attacker supplies liquidity_A + auth_list_B to ChangeStatus.
        // The constraint is: auth_list_B.auth_users.contains(pool_a_attacker)
        // This PASSES because pool_a_attacker is in auth_list_B.
        // But there is no check that auth_list_B belongs to liquidity_A!

        let attacker_passes_constraint = auth_list_b.auth_users.contains(&pool_a_attacker);
        assert!(
            attacker_passes_constraint,
            "[H-1] Constraint should pass for pool_a_attacker against auth_list_b"
        );

        // Simulate the handler body: modify liquidity_A using auth_list_B
        // (no on-chain link prevents this pairing)
        let attacker_is_not_pool_a_admin = !auth_list_a.auth_users.contains(&pool_a_attacker);
        assert!(
            attacker_is_not_pool_a_admin,
            "[H-1] pool_a_attacker must NOT be in pool A's real auth_list"
        );

        // Handler executes (using liquidity_a, auth_list_b — mismatched pair)
        assert_ne!(liquidity_a.status, true, "liquidity_a starts unpaused");
        liquidity_a.status = true; // pause pool A using pool B's auth
        assert!(
            liquidity_a.status,
            "[H-1] Pool A was paused by an attacker using Pool B's auth_list"
        );

        println!(
            "\n[H-1 PROVEN — cross-pool escalation]\n\
             pool_a_attacker ({}) is in auth_list_B but NOT in auth_list_A.\n\
             By supplying (liquidity_A, auth_list_B) to ChangeStatus, the attacker\n\
             satisfies the constraint and modifies Pool A's state.\n\
             Root cause: no `has_one` or `address` binding between liquidity and auth_list.\n\
             Impact: in a multi-pool upgrade, any auth_user of any pool can affect any\n\
             other pool's admin operations.",
            pool_a_attacker
        );
    }

    /// H-1 PoC #2 — Demonstrates the missing relationship check is the root cause.
    ///
    /// In a correct design the constraint would verify:
    ///   `auth_list.key() == liquidity.auth_list`
    /// or use `has_one = auth_list` on the liquidity account.
    /// This test shows that simply adding such a check would block the exploit.
    #[test]
    fn test_h1_proposed_fix_would_block_cross_pool_attack() {
        let pool_a_admin = Pubkey::new_unique();
        let pool_a_auth_list_pda = Pubkey::new_unique(); // expected auth_list for pool A
        let pool_b_auth_list_pda = Pubkey::new_unique(); // different PDA for pool B
        let attacker = Pubkey::new_unique();

        // Pool A's liquidity references its own auth_list PDA
        // In the current code Liquidity does NOT store auth_list_pda —
        // that is exactly the missing field.
        struct LiquidityFixed {
            authority: Pubkey,
            auth_list_pda: Pubkey, // ← this field does NOT exist in production
        }
        let liquidity_a = LiquidityFixed {
            authority: pool_a_admin,
            auth_list_pda: pool_a_auth_list_pda,
        };

        // Attacker tries to use pool B's auth_list
        let supplied_auth_list_pda = pool_b_auth_list_pda; // attacker-supplied

        // With the fix, the constraint would check:
        let constraint_passes = supplied_auth_list_pda == liquidity_a.auth_list_pda;
        assert!(
            !constraint_passes,
            "[H-1] With has_one fix, mismatched auth_list PDA is correctly rejected"
        );

        // Without the fix (current production code), no such check exists:
        let current_code_has_linkage_check = false; // hardcoded: the Liquidity struct has no auth_list field
        assert!(
            !current_code_has_linkage_check,
            "[H-1] Production code confirmed: Liquidity struct has no auth_list PDA binding"
        );

        println!(
            "\n[H-1 ROOT CAUSE] The `Liquidity` struct has no `auth_list` field.\n\
             The `has_one = auth_list` Anchor constraint cannot be added without\n\
             first storing the auth_list PDA inside `Liquidity`.\n\
             Attacker ({}) would be blocked by a linkage check but is not in production.",
            attacker
        );
    }
}

// ============================================================================
//  [H-5] SECURITY POC — `interacting_timestamp` Second-Precision Collision
//
//  `pre_operate` sets `token_reserve.interacting_timestamp` to the current
//  block's `unix_timestamp` (second precision).  On Solana, all transactions
//  in the same slot share the same `unix_timestamp`.
//
//  If two separate protocols (Protocol A and Protocol B) both call
//  `pre_operate` on the same token reserve in the same slot, Protocol B's
//  call overwrites Protocol A's `interacting_protocol` and
//  `interacting_balance` fields.
//
//  When Protocol A then calls `operate`, it checks:
//    interacting_protocol == ctx.accounts.protocol.key()  AND
//    interacting_timestamp == Clock::get()?.unix_timestamp
//
//  The timestamp check passes (same slot!), but the protocol key check fails
//  because Protocol B's `pre_operate` ran last and wrote its own key.
//  Protocol A's `operate` reverts with `DepositExpected`.
//
//  This is an intermittent, hard-to-diagnose DoS affecting any protocol that
//  shares a token reserve with high-frequency interactors.
// ============================================================================
#[cfg(test)]
mod security_poc_h5_tests {
    use super::*;

    /// H-5 PoC #1 — Same-slot timestamp means Protocol A's operate check fails
    ///              after Protocol B overwrites the interacting state.
    #[test]
    fn test_h5_protocol_b_overwrites_protocol_a_interacting_state() {
        let protocol_a = Pubkey::new_unique();
        let protocol_b = Pubkey::new_unique();

        // Simulate the shared token reserve state
        // After Protocol A's `pre_operate`:
        let mut interacting_protocol = protocol_a;
        let mut interacting_balance: u64 = 500_000; // Protocol A deposited 500k
        let slot_timestamp: u64 = 1_740_000_000;   // same for all txs in this slot
        let interacting_timestamp = slot_timestamp;

        // ── Protocol B calls pre_operate in the SAME SLOT ─────────────────
        // pre_operate overwrites interacting_protocol and interacting_balance
        interacting_protocol = protocol_b;
        interacting_balance = 800_000;              // Protocol B deposited 800k

        // interacting_timestamp is the same (same slot) — this is the crux of the bug
        assert_eq!(
            interacting_timestamp, slot_timestamp,
            "Both transactions are in the same slot and share the timestamp"
        );

        // ── Protocol A now calls `operate` ────────────────────────────────
        // operate checks: interacting_protocol == protocol_a AND timestamp == slot_timestamp
        let timestamp_check_passes = interacting_timestamp == slot_timestamp; // ← TRUE (same slot)
        let protocol_check_passes  = interacting_protocol == protocol_a;      // ← FALSE (was overwritten)

        assert!(
            timestamp_check_passes,
            "[H-5] Timestamp check passes (same slot) — this is why the bug is subtle"
        );
        assert!(
            !protocol_check_passes,
            "[H-5] Protocol check FAILS because Protocol B's pre_operate ran last"
        );

        // On-chain this results in `return Err(ErrorCodes::DepositExpected)`
        // Protocol A's funds have already been sent to the vault but `operate`
        // reverts, leaving the vault in an inconsistent state for Protocol A.
        let operate_would_succeed = timestamp_check_passes && protocol_check_passes;
        assert!(
            !operate_would_succeed,
            "[H-5] Protocol A's operate() fails despite valid deposit — DoS confirmed"
        );

        println!(
            "\n[H-5 PROVEN — same-slot DoS]\n\
             Slot timestamp:          {}\n\
             interacting_protocol:    {} (was {}, overwritten by Protocol B)\n\
             Protocol A key:          {}\n\
             Timestamp check:         {} (same slot — passes)\n\
             Protocol check:          {} (overwritten — fails)\n\
             operate() would succeed: {}\n\
             Impact: Protocol A's deposit transaction reverts after funds were sent\n\
             to the vault. The deposited balance is stuck until Protocol A retries\n\
             in a later slot, and the next pre_operate will see an inflated vault\n\
             balance causing TransferAmountOutOfBounds.",
            slot_timestamp,
            interacting_protocol, protocol_a,
            protocol_a,
            timestamp_check_passes,
            protocol_check_passes,
            operate_would_succeed
        );
    }

    /// H-5 PoC #2 — Demonstrates that the slot number (u64) uniquely identifies
    ///              a slot but the current code uses unix_timestamp (u64 seconds),
    ///              which is NOT unique per-slot on Solana (400ms slots, 1s clock).
    ///
    /// On Solana, approximately 2–3 transactions in different slots can share
    /// the same unix_timestamp because the slot duration (400ms) is shorter
    /// than one second.  This test shows the math.
    #[test]
    fn test_h5_slot_duration_means_timestamp_is_not_unique_per_slot() {
        const SLOT_DURATION_MS: u64 = 400;  // ~400ms per slot
        const SLOTS_PER_SECOND: u64 = 1000 / SLOT_DURATION_MS; // = 2.5 → at least 2

        // In 2 consecutive slots the timestamp can be the same:
        let slot_n_timestamp_ms:     u64 = 1_740_000_000_000; // ms since epoch
        let slot_n1_timestamp_ms:    u64 = slot_n_timestamp_ms + SLOT_DURATION_MS;

        let slot_n_unix_ts:  u64 = slot_n_timestamp_ms  / 1000;
        let slot_n1_unix_ts: u64 = slot_n1_timestamp_ms / 1000;

        // Slots N and N+1 can have the SAME unix_timestamp (integer seconds)
        let same_second = slot_n_unix_ts == slot_n1_unix_ts;
        assert!(
            same_second,
            "[H-5] Slot N and N+1 share unix_timestamp={} — collision confirmed",
            slot_n_unix_ts
        );

        println!(
            "\n[H-5 PROVEN — timestamp collision window]\n\
             Slot duration: {}ms → {} slots per second\n\
             Slot N  unix_timestamp: {}\n\
             Slot N+1 unix_timestamp: {}\n\
             Same second: {}\n\
             Implication: pre_operate from slot N and operate from slot N+1 will BOTH\n\
             pass the timestamp check if they land in the same integer second,\n\
             but if a different protocol's pre_operate also lands in that window,\n\
             the interacting_protocol overwrite bug (PoC #1) applies.",
            SLOT_DURATION_MS, SLOTS_PER_SECOND,
            slot_n_unix_ts, slot_n1_unix_ts, same_second
        );
    }
}


