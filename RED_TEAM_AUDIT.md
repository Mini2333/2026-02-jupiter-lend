# Red Team Security Audit — Jupiter Lend

**Date:** 2026-03-02  
**Scope:** All Rust programs in `/programs` (liquidity, vaults, oracle, flashloan, lending, lendingRewardRateModel)  
**Methodology:** Manual white-box code review of account constraints, access control, math, oracle integration, and economic invariants.

---

## Executive Summary

This audit identified **2 critical**, **5 high**, and **4 medium** severity issues across the Jupiter Lend protocol. The most system-breaking findings concern unauthenticated admin initialization (front-runnable by any Solana account at deployment), a missing `has_one` linkage between the singleton `Liquidity` and `AuthorizationList` PDAs in several guardian/auth contexts, and the ability for any auth user to both **pause and unpause** the entire protocol without restriction.

---

## Findings

### [C-1] CRITICAL — Admin PDA Initialization Front-Running: Any Caller Can Seize Full Protocol Control

**Affected programs:** `liquidity`, `vaults`, `flashloan`, `oracle`, `lending`  
**Affected accounts:** `Liquidity` PDA, `VaultAdmin` PDA, `FlashloanAdmin` PDA, `OracleAdmin` PDA, `LendingAdmin` PDA

**Description:**  
Every program's singleton admin account is initialized by an instruction that carries **no access control** — any signer can be the first caller:

```rust
// programs/vaults/src/state/context.rs
pub struct InitVaultAdmin<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,          // ← any wallet

    #[account(
        init,
        seeds = [VAULT_ADMIN_SEED],
        ...
    )]
    pub vault_admin: Account<'info, VaultAdmin>,
    ...
}
```

The same pattern appears in `InitFlashloanAdmin`, `InitLiquidity`, `InitAdmin` (oracle), and `InitLendingAdmin`. The initializer sets `authority` and `auths` to whichever pubkey they supply:

```rust
pub fn init_vault_admin(ctx: Context<InitVaultAdmin>, liquidity: Pubkey, authority: Pubkey) -> Result<()> {
    vault_admin.authority = authority;   // caller-controlled
    vault_admin.auths.push(authority);
    ...
}
```

**Attack scenario:**  
1. Attacker monitors chain for a freshly deployed Jupiter Lend program (e.g., via program-deploy listener).  
2. Attacker submits `init_vault_admin` / `init_liquidity` / `init_flashloan_admin` etc. before the deployment team does, with their own pubkey as `authority`.  
3. The PDA is a singleton (`seeds = [VAULT_ADMIN_SEED]`). After the attacker initializes it, the deployment team's own call will **fail** ("already in use").  
4. Attacker now controls all protocol parameters: vault risk settings, oracle addresses, liquidity rates, pause/unpause, revenue collection, and can drain funds through malicious config.

**Impact:** Complete takeover of the protocol at no cost beyond a transaction fee.

**Recommendation:**  
Add a hardcoded `PROTOCOL_INIT_AUTH` constraint (already used in some other instructions) to these initialization contexts, or derive admin authority from the program upgrade authority / a well-known multisig:

```rust
#[account(mut, address = PROTOCOL_INIT_AUTH @ ErrorCodes::OnlyInitAuth)]
pub signer: Signer<'info>,
```

---

### [C-2] CRITICAL — `ChangeStatus`: Any Auth User Can **Unpause** the Protocol Regardless of Why It Was Paused

**Affected program:** `liquidity`  
**Affected instruction:** `change_status`

**Description:**  
The `ChangeStatus` context grants identical privilege to **set or clear** the global pause flag to anyone in `auth_users`:

```rust
pub struct ChangeStatus<'info> {
    #[account()]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub liquidity: Account<'info, Liquidity>,

    #[account(constraint = auth_list.auth_users.contains(&authority.key()) @ ErrorCodes::OnlyAuth)]
    pub auth_list: Account<'info, AuthorizationList>,
}
```

There is no separation between the power to pause and the power to unpause. If governance (the authority) pauses the protocol in response to an active exploit, any of the 10 `auth_users` (which includes automated bots, keeper accounts, and sub-signers) can immediately unpause it:

```rust
pub fn change_status(context: Context<ChangeStatus>, status: bool) -> Result<()> {
    context.accounts.liquidity.status = status;   // true=pause, false=unpause
    ...
}
```

Compare this with the design intent in `PauseUser` — which deliberately uses the `guardians` list instead of `auth_users` for emergency actions — suggesting the protocol wants finer role separation for emergencies.

**Attack scenario:**  
1. An active exploit is discovered. Governance pauses the protocol (`status = true`).  
2. Any of the up to 10 `auth_users` (e.g., a compromised keeper bot key) calls `change_status(false)`.  
3. The pause is immediately reversed. The exploit can resume.

**Impact:** Emergency pause is ineffective as a last-resort protection.

**Recommendation:**  
Restrict `unpause` (setting `status = false`) to the `authority` (governance multisig) only. Allow `pause` by auth users or guardians. The simplest fix:

```rust
pub fn change_status(context: Context<ChangeStatus>, status: bool) -> Result<()> {
    // Only authority can unpause; auths can pause
    if !status && context.accounts.authority.key() != context.accounts.liquidity.authority {
        return Err(ErrorCodes::OnlyLiquidityAuthority.into());
    }
    ...
}
```

---

### [H-1] HIGH — Missing Account Relationship Constraint: `liquidity` ↔ `auth_list` in Multiple Admin Contexts

**Affected program:** `liquidity`  
**Affected contexts:** `ChangeStatus`, `CollectRevenue`, `UpdateRateData`, `UpdateTokenConfig`, `UpdateUserClass`, `UpdateUserWithdrawalLimit`, `UpdateUserSupplyConfig`, `UpdateUserBorrowConfig`

**Description:**  
None of these contexts include a constraint that links the `liquidity` account to the `auth_list` account. For example:

```rust
pub struct ChangeStatus<'info> {
    #[account()]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub liquidity: Account<'info, Liquidity>,      // ← no linkage to auth_list

    #[account(constraint = auth_list.auth_users.contains(&authority.key()) @ ErrorCodes::OnlyAuth)]
    pub auth_list: Account<'info, AuthorizationList>,  // ← no linkage to liquidity
}
```

Although in the current deployment there is only one `liquidity` PDA and one `auth_list` PDA (both singletons), there is no on-chain enforcement of their relationship. If the program were ever upgraded to support multiple liquidity pools, or if an attacker can somehow supply a crafted account of the correct type, the missing constraint would allow cross-account privilege escalation.

Furthermore, for `UpdateUserClass`:

```rust
pub struct UpdateUserClass<'info> {
    #[account()]
    pub authority: Signer<'info>,

    #[account(mut, constraint = auth_list.auth_users.contains(&authority.key()) @ ErrorCodes::OnlyAuth)]
    pub auth_list: Account<'info, AuthorizationList>,
    // ← no liquidity account at all; any auth_list with authority as member passes
}
```

This context doesn't even include the `liquidity` account, so it does not check whether the protocol is locked down before allowing admin changes.

**Recommendation:**  
Add `has_one = auth_list` to the `liquidity` account in every admin context, add a `auth_list` field to the `Liquidity` struct, and verify the global lock before admin mutations:

```rust
#[account(mut, has_one = auth_list, constraint = !liquidity.is_locked() @ ErrorCodes::ProtocolLockdown)]
pub liquidity: Account<'info, Liquidity>,
```

---

### [H-2] HIGH — Vault Branch, Tick, and TickHasDebt Infrastructure Accounts Are Permissionlessly Initializable

**Affected program:** `vaults`  
**Affected instructions:** `init_branch`, `init_tick`, `init_tick_id_liquidation`, `init_tick_has_debt_array`

**Description:**  
All four instructions accept any signer with no authorization check:

```rust
pub struct InitBranch<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,          // ← any wallet

    pub vault_config: AccountLoader<'info, VaultConfig>,   // read-only, no auth check
    ...
}
```

The implementation only validates that the `vault_id` matches:

```rust
pub fn init_branch(ctx: Context<InitBranch>, vault_id: u16, branch_id: u32) -> Result<()> {
    let vault_config = &ctx.accounts.vault_config.load()?;
    if vault_id != vault_config.vault_id { return Err(...); }
    ...
}
```

**Attack scenarios:**

1. **Griefing / DoS at deployment:** An attacker pre-initializes all expected tick and branch PDAs before the vault admin does, consuming their expected PDA slots. Since PDAs are singletons (same seeds → same address), the admin's own initialization calls would fail with "already initialized." The vault would not function.

2. **Tick pre-seeding:** An attacker could initialize tick accounts with `tick` values that they know the vault will need. While the data stored is deterministic from the PDA seed, the attacker is paying rent and "donating" accounts. Combined with other issues, this could be used to manipulate liquidation sequencing in subtle ways.

3. **`init_tick_id_liquidation` mismatch:** The `total_ids` parameter is caller-supplied and is used to compute `tick_map = (total_ids + 2) / 3`. If an attacker can supply an unexpected `total_ids` value (different from what the liquidation engine later expects), subsequent liquidations may fail to find the correct tick ID liquidation account.

**Recommendation:**  
Add an auth check (e.g., `auth_list.auth_users.contains(&signer.key())` or `signer.key() == PROTOCOL_INIT_AUTH`) to all four contexts.

---

### [H-3] HIGH — Oracle Staleness Window of 2 Hours for Liquidations Enables Price-Based Attacks

**Affected program:** `oracle`  
**Constant:** `MAX_AGE_LIQUIDATE = 7200` seconds

**Description:**  
The oracle's staleness check for liquidation-mode price reads allows prices up to 2 hours old:

```rust
pub const MAX_AGE_LIQUIDATE: u64 = 7200; // 2 hours
pub const MAX_AGE_OPERATE: u64 = 600;    // 10 minutes
```

The Pyth, Redstone, and Chainlink readers apply this tolerance:

```rust
let maximum_age = if is_liquidate.is_some() && is_liquidate.unwrap() {
    MAX_AGE_LIQUIDATE
} else {
    MAX_AGE_OPERATE
};
```

**Attack scenarios:**

1. **Liquidating healthy positions with stale prices:** During a period of high volatility (e.g., a flash crash followed by rapid recovery), an attacker could use a price from up to 2 hours ago — when the asset was at a temporarily depressed price — to liquidate positions that are currently well-collateralised at the current market price.

2. **Preventing liquidation of underwater positions:** If the oracle has not published a fresh price within 2 hours (e.g., oracle downtime), the price used for liquidation checks could be stale enough to make an underwater position appear healthy.

3. **Confidence threshold bypass:** Pyth's confidence interval check uses a looser bound for liquidations (`CONFIDENCE_SCALE_FACTOR_LIQUIDATE = 25`, i.e., reject only if conf > 4% of price) vs. operate (`CONFIDENCE_SCALE_FACTOR_OPERATE = 50`, i.e., reject if conf > 2%). Combined with the 2-hour staleness, this maximises the attack surface for manipulation.

**Recommendation:**  
Reduce `MAX_AGE_LIQUIDATE` to a more conservative value (e.g., 15–30 minutes). If oracle outage is a genuine concern, implement a circuit breaker that pauses liquidations when the oracle is stale rather than accepting arbitrarily old prices.

---

### [H-4] HIGH — `init_claim_account` Is Permissionless: Griefing and Rent Hijacking

**Affected program:** `liquidity`  
**Affected instruction:** `init_claim_account`

**Description:**  
The `InitClaimAccount` context allows any signer to create a claim account for **any** `user` pubkey:

```rust
pub struct InitClaimAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,      // ← any wallet, not necessarily `user`

    #[account(
        init,
        payer = signer,
        seeds = [USER_CLAIM_SEED, user.key().as_ref(), mint.key().as_ref()],
        ...
    )]
    pub claim_account: AccountLoader<'info, UserClaim>,
    ...
}
```

The `user` pubkey is taken from the instruction argument, not enforced to be the signer.

**Impact:**

1. **Rent extraction / griefing:** An attacker creates claim accounts for high-volume users before they do. The attacker pays rent but the user can never reclaim that rent (the account can only be closed by the user when balance = 0, per `CloseClaimAccount`). This is a relatively low-cost annoyance for each victim.

2. **DoS on claim flow:** If a user expects to create their own claim account in the same transaction as a `operate` with `TransferType::CLAIM`, a front-runner could pre-create it and cause the user's account init to fail, breaking the transaction.

3. **Unexpected claim balance manipulation:** A bot could continuously pre-create claim accounts for every new protocol address, increasing the `total_claim_amount` bookkeeping overhead and potentially confusing frontends.

**Recommendation:**  
Require `signer == user` in the context, or derive the claim account from the signer's key rather than an instruction argument:

```rust
pub struct InitClaimAccount<'info> {
    #[account(mut)]
    pub user: Signer<'info>,    // user must sign for their own claim account
    ...
    // derive seeds from user.key() directly, not from an instruction arg
}
```

---

### [H-5] HIGH — `interacting_timestamp` Second-Level Precision: Same-Block Protocol Interference

**Affected program:** `liquidity`  
**Affected instructions:** `pre_operate`, `operate`

**Description:**  
`pre_operate` records the current block timestamp at **second** granularity into `token_reserve.interacting_timestamp`:

```rust
token_reserve.interacting_timestamp = Clock::get()?.unix_timestamp.cast()?;
```

`operate` then validates both the stored protocol key AND the timestamp:

```rust
if token_reserve.interacting_protocol != ctx.accounts.protocol.key()
    || token_reserve.interacting_timestamp != Clock::get()?.unix_timestamp.cast::<u64>()?
{
    return Err(ErrorCodes::DepositExpected.into());
}
```

On Solana, all transactions confirmed in the same slot share the same `unix_timestamp`. Two separate protocols that both call `pre_operate` on the **same token reserve** in the same slot will each overwrite the other's `interacting_protocol` / `interacting_balance`:

- Slot N: Protocol A calls `pre_operate` → `interacting_protocol = A`, `interacting_balance = B₁`
- Slot N: Protocol B calls `pre_operate` → `interacting_protocol = B`, `interacting_balance = B₂` (**overwrites A**)
- Slot N: Protocol A calls `operate` → check fails: `interacting_protocol == B ≠ A` → reverts with `DepositExpected`

While write conflicts cause serialization on Solana (preventing true concurrency), **within a single slot** a legitimately confirmed tx by Protocol B that runs after Protocol A's `pre_operate` but before Protocol A's `operate` is possible when both are in different transactions in the same block.

**Impact:** Protocol A's deposit transaction silently reverts. Funds have already been transferred to the vault (before `operate` is called) but the `operate` fails. The `interacting_balance` has been overwritten, so the next `pre_operate` by A in a later block will see the vault with extra funds and will calculate a lower `net_amount_in`, causing `TransferAmountOutOfBounds`.

In practice this creates intermittent, hard-to-diagnose transaction failures for any protocol that shares a token reserve with a high-frequency interactor.

**Recommendation:**  
Add a nonce or slot number to the interacting state to uniquely identify a `pre_operate` / `operate` pair, and verify the match on the `operate` side. Alternatively, use a per-protocol lock account rather than a shared field on `TokenReserve`.

---

### [M-1] MEDIUM — Vault `Operate` Context: Missing `has_one = vault_state` on `vault_config`

**Affected program:** `vaults`  
**Affected context:** `Operate`

**Description:**  
In the `Operate` context, `vault_config` and `vault_state` are both loaded but there is no on-chain constraint linking them:

```rust
pub vault_config: AccountLoader<'info, VaultConfig>,   // no seeds/has_one
#[account(mut)]
pub vault_state: AccountLoader<'info, VaultState>,     // no has_one = vault_config
```

The relationship is only validated inside `verify_operate` at runtime:

```rust
if vault_state.vault_id != vault_config.vault_id {
    return Err(error!(ErrorCodes::VaultInvalidVaultId));
}
```

An attacker could supply a mismatched pair (e.g., `vault_config` for vault 1, `vault_state` for vault 2). While `verify_operate` catches this, the validation happens after account loading, leaving a window for confusion attacks if verification logic is ever changed or bypassed.

**Recommendation:**  
Add PDA seed constraints to both accounts to bind them to the same `vault_id`, or add `has_one = vault_state` to `vault_config` by storing a cross-reference.

---

### [M-2] MEDIUM — Rate Model V1 Allows Declining Rate Before Kink (Unchecked Monotonicity)

**Affected program:** `liquidity`  
**Affected instruction:** `update_rate_data_v1`

**Description:**  
The V1 rate model validation enforces:

```rust
if rate_data.kink == 0 ||
    rate_data.kink >= FOUR_DECIMALS ||
    rate_data.rate_at_utilization_kink > rate_data.rate_at_utilization_max
{
    return Err(ErrorCodes::InvalidParams.into());
}
```

This does **not** require `rate_at_utilization_zero <= rate_at_utilization_kink`. An admin can configure a rate model where `rate_at_zero = 5000` and `rate_at_kink = 100`, producing a rate curve that **decreases** from 50% to 1% as utilization rises from 0% to the kink. This is economically perverse — it incentivizes over-utilization (borrowers pay less as more is borrowed).

Such a configuration would appear valid, pass all tests, and could be used to silently drain a token reserve by making high-utilisation borrowing extremely cheap.

**Recommendation:**  
Add a monotonicity check: `rate_at_utilization_zero <= rate_at_utilization_kink`. The same check already implicitly exists for kink-to-max (`rate_at_kink <= rate_at_max`).

---

### [M-3] MEDIUM — Flashloan Payback Validation Iterates in Reverse, Missing Forward-Order Payback Detection

**Affected program:** `flashloan`  
**Affected function:** `validate_payback_instruction_exists`

**Description:**  
The validator iterates instructions in **reverse** after the borrow index:

```rust
for i in (search_start..total_instructions).rev() {
    ...
    Ok(false) => {
        // throw error if invalid instruction is found
        return Err(ErrorCodes::FlashloanInvalidInstruction.into());
    }
}
```

Any instruction belonging to the flashloan program that is **not** a valid payback causes an immediate error. This correctly prevents interleaving other flashloan instructions. However, the reverse iteration means the validator finds the **last** valid payback instruction first, and only then enforces there is not a second one. If there are two flashloan borrow instructions in the same transaction (which is independently prevented by `is_flashloan_active`), but the payback validation logic is reached before the second borrow's execution, a subtle race with `set_flashloan_as_active` could allow the state to be set inconsistently.

Furthermore, `is_flashloan_payback_instruction` checks all accounts of the payback instruction against `ctx.accounts.to_account_infos()` of the borrow context. The `signer_borrow_token_account` in the borrow context is `init_if_needed` — this means a **new** ATA may be created for the borrow, but the payback instruction's accounts, which are passed at transaction construction time, may reference the account **before** it exists. If the account creation fails mid-transaction, the payback validation could accept an instruction that can never actually execute.

**Recommendation:**  
Consider adding an explicit forward-order check to confirm the payback instruction appears after all user instructions (not just after the borrow), and validate that the signer's ATA exists before accepting the payback reference.

---

### [M-4] MEDIUM — `saturating_sub` in Exchange Price and Claim Calculations May Silently Mask Bad Debt

**Affected programs:** `liquidity`, `vaults`

**Description:**  
Several financially critical paths use `saturating_sub` instead of `safe_sub`:

```rust
// token_reserve.rs - calc_revenue
let revenue_amount: u128 = liquidity_token_balance
    .safe_add(total_borrow)?
    .saturating_sub(self.total_claim_amount.cast()?);

Ok(revenue_amount.saturating_sub(total_supply))   // ← can silently return 0
```

```rust
// user_supply_position.rs
let mut current_withdrawal_limit: u128 =
    last_withdrawal_limit.saturating_sub(withdrawal_amount);  // ← silent underflow
```

```rust
// token_reserve.rs - set_new_total_supply_with_interest
current_supply_raw_interest =
    current_supply_raw_interest.saturating_sub(new_supply_interest_raw.abs().cast()?);
```

When `saturating_sub` clamps to 0 instead of propagating an error, the protocol may:
- Report zero revenue when revenue is actually negative (indicating bad debt / insolvency).
- Set withdrawal limits to 0 instead of surfacing an accounting inconsistency.
- Silently reduce total supply below the actual user supply amounts, making future invariant checks unreliable.

**Recommendation:**  
Replace `saturating_sub` with `safe_sub` in all paths where underflow indicates a protocol invariant violation. Reserve `saturating_sub` only for explicitly documented "best-effort" paths (e.g., removing a user from a tick when the exact accounting doesn't matter).

---

## Summary Table

| ID  | Severity | Title |
|-----|----------|-------|
| C-1 | Critical | Admin PDA initialization is front-runnable by any signer |
| C-2 | Critical | Any auth user can unpause a deliberately-paused protocol |
| H-1 | High     | Missing `liquidity` ↔ `auth_list` relationship in admin contexts |
| H-2 | High     | Vault branch/tick infrastructure initializable by anyone |
| H-3 | High     | 2-hour oracle staleness window enables liquidation price attacks |
| H-4 | High     | `init_claim_account` is permissionless; griefing and rent hijacking |
| H-5 | High     | `interacting_timestamp` second-precision allows same-block interference |
| M-1 | Medium   | Vault `Operate` missing binding constraint between `vault_config` and `vault_state` |
| M-2 | Medium   | Rate model V1 allows economically perverse declining-rate-before-kink curve |
| M-3 | Medium   | Flashloan payback validation reverse iteration has edge-case gaps |
| M-4 | Medium   | `saturating_sub` in financial paths silently masks bad debt and accounting errors |

---

## Notes on Out-of-Scope / Design Choices

- **`update_authority` hardcoded to `GOVERNANCE_MS`:** The authority can only be transferred to one hardcoded address. While intentional (prevents unilateral re-assignment), it means the protocol cannot adapt if the governance address changes. Consider using a two-step authority transfer with a timelock instead.
- **Global flashloan state limits composability:** Only one flashloan can be active at a time across all tokens. This is by design but limits multi-token flash loan compositions.
- **`PROTOCOL_INIT_AUTH` backdoor:** Several initialization contexts allow `PROTOCOL_INIT_AUTH` as an alternative to `auth_users`. This hardcoded key represents a permanent privileged capability that survives any governance rotation and should be documented prominently or removed post-launch.
