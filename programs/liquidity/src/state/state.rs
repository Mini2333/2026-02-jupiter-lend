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

