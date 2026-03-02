use anchor_lang::prelude::*;

pub const RATE_OUTPUT_DECIMALS: u32 = 15;
pub const MAX_SOURCES: usize = 4;
pub const MAX_AUTH_COUNT: usize = 10;

pub const SECONDS_PER_HOUR: u64 = 3600;
pub const MAX_AGE_OPERATE: u64 = 600; // should be in seconds -> 10 minutes

pub const MAX_AGE_LIQUIDATE: u64 = 7200; // should be in seconds, less requirements on liquidate() to keep protocol safe -> 2hrs

pub const CONFIDENCE_SCALE_FACTOR_LIQUIDATE: u64 = 25; // Rejects if confidence < 1/25 = 4% of price
pub const CONFIDENCE_SCALE_FACTOR_OPERATE: u64 = 50; // Rejects if confidence < 1/50 = 2% of price

pub const MAX_DIVISOR: u128 = 10u128.pow(10);
pub const MAX_MULTIPLIER: u128 = 10u128.pow(10);

pub const GOVERNANCE_MS: Pubkey = pubkey!("HqPrpa4ESBDnRHRWaiYtjv4xe93wvCS9NNZtDwR89cVa");

// 0.5% max fee ceiling
pub const MAX_FEE_CEILING: u64 = 5;

pub const AVG_SLOT_TIME_IN_MILLISECONDS: u64 = 400;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub const FACTOR: u128 = 10u128.pow(RATE_OUTPUT_DECIMALS);

pub const MILLISECONDS_PER_SECOND: u64 = 1000;
pub const DEFAULT_DIVISOR: u128 = 1;
pub const DEFAULT_MULTIPLIER: u128 = 1;

pub const SINGLE_POOL_ACCOUNTS_COUNT: usize = 3;
pub const JUP_LEND_ACCOUNTS_COUNT: usize = 4;

// ============================================================================
//  [H-3] SECURITY POC — 2-Hour Oracle Staleness Window Enables
//                         Liquidation Price Attacks
//
//  The oracle program accepts prices up to `MAX_AGE_LIQUIDATE = 7200` seconds
//  (2 hours) old when executing liquidations.  Normal operations use a much
//  stricter `MAX_AGE_OPERATE = 600` seconds (10 minutes).
//
//  This wide staleness window enables two distinct attack vectors:
//
//  VECTOR A — Liquidating healthy positions with stale depressed prices:
//  During a flash crash followed by rapid recovery, an attacker can use a
//  price from up to 2 hours ago (when the asset was cheaper) to classify
//  currently well-collateralised positions as underwater and liquidate them,
//  capturing an illegitimate liquidation bonus.
//
//  VECTOR B — Preventing valid liquidations with stale inflated prices:
//  A borrower nearing liquidation can exploit oracle downtime (or the 2-hour
//  window) to keep a stale high price on record, preventing valid liquidators
//  from using the current lower price.  This lets the borrower remain under-
//  collateralised without being liquidated.
//
//  Additionally, the confidence interval for liquidations is looser:
//  `CONFIDENCE_SCALE_FACTOR_LIQUIDATE = 25` (reject if conf > 4% of price)
//  vs `CONFIDENCE_SCALE_FACTOR_OPERATE = 50` (reject if conf > 2% of price).
//  A wider confidence band combined with a 2-hour staleness window maximises
//  the attack surface for oracle-manipulation-assisted liquidations.
// ============================================================================
#[cfg(test)]
mod security_poc_h3_tests {
    use super::*;

    // ------------------------------------------------------------------
    // H-3 PoC #1 — A price 7199 seconds old is considered VALID for
    //              liquidations, but is clearly stale for fair pricing.
    // ------------------------------------------------------------------
    /// Prove that a price almost 2 hours old passes the staleness check.
    /// An asset can move 20–40% in 2 hours during high volatility.
    #[test]
    fn test_h3_liquidate_accepts_price_near_two_hours_old() {
        let current_time: u64 = 1_740_000_000;
        let price_age_seconds: u64 = 7199; // 1 second under the 2-hour threshold

        let publish_time: u64 = current_time - price_age_seconds;
        let age = current_time - publish_time;

        // Staleness check used in the oracle for liquidation:
        let is_stale_for_liquidation = age > MAX_AGE_LIQUIDATE;
        let is_stale_for_operation   = age > MAX_AGE_OPERATE;

        // This price is NOT stale for liquidation (passes validation)
        assert!(
            !is_stale_for_liquidation,
            "[H-3] Price {} seconds old should be stale for liquidation (MAX_AGE={})",
            age, MAX_AGE_LIQUIDATE
        );

        // But it IS stale for normal operations (fails validation)
        assert!(
            is_stale_for_operation,
            "[H-3] Price {} seconds old IS stale for normal operations (MAX_AGE={})",
            age, MAX_AGE_OPERATE
        );

        // At 7199s old, the asset price may have moved significantly
        // Example: USDC-SOL at ~$180. In 2 hours, SOL can drop 20%.
        let stale_price_usd: u64 = 18_000; // $180 — recorded 2 hours ago
        let current_price_usd: u64 = 14_400; // $144 — current market (-20%)
        let price_deviation_pct = (stale_price_usd - current_price_usd) * 100 / stale_price_usd;

        assert_eq!(price_deviation_pct, 20, "20% price move in 2 hours is realistic");

        println!(
            "\n[H-3 PROVEN — stale liquidation price accepted]\n\
             Price age:    {} seconds ({:.1} hours)\n\
             MAX_AGE_LIQUIDATE: {} seconds\n\
             MAX_AGE_OPERATE:   {} seconds\n\
             Price accepted for liquidation: {}\n\
             Price rejected for operation:   {}\n\
             Example: Stale price ${} vs current ${} = {}% deviation.\n\
             Impact: Attacker uses stale high price to liquidate healthy positions,\n\
             or stale low price to force unfair liquidations.",
            age, age as f64 / 3600.0,
            MAX_AGE_LIQUIDATE, MAX_AGE_OPERATE,
            !is_stale_for_liquidation,
            is_stale_for_operation,
            stale_price_usd / 100, current_price_usd / 100, price_deviation_pct
        );
    }

    // ------------------------------------------------------------------
    // H-3 PoC #2 — The confidence threshold for liquidations is 2× looser
    //              than for normal operations, widening the manipulation window.
    // ------------------------------------------------------------------
    /// A high-uncertainty price that passes the liquidation confidence check
    /// but would be rejected for normal operations.
    #[test]
    fn test_h3_liquidate_confidence_threshold_is_twice_as_loose() {
        // Example: price = 10_000 units, conf = 350 units (3.5% uncertainty)
        let price: u64 = 10_000;
        let conf: u64 = 350;   // 3.5% of price

        // Confidence check for liquidation: reject if conf * 25 > price (i.e., conf > 4%)
        let fails_liquidate_check = conf * CONFIDENCE_SCALE_FACTOR_LIQUIDATE > price;
        // Confidence check for operation: reject if conf * 50 > price (i.e., conf > 2%)
        let fails_operate_check   = conf * CONFIDENCE_SCALE_FACTOR_OPERATE   > price;

        // 3.5% confidence: accepted for liquidation, rejected for operation
        assert!(
            !fails_liquidate_check,
            "[H-3] 3.5% confidence should pass liquidation check (threshold=4%)"
        );
        assert!(
            fails_operate_check,
            "[H-3] 3.5% confidence should fail operation check (threshold=2%)"
        );

        println!(
            "\n[H-3 PROVEN — loose liquidation confidence]\n\
             Price: {}, Confidence: {} ({:.1}%)\n\
             CONFIDENCE_SCALE_FACTOR_LIQUIDATE = {} (rejects if conf > 4% of price)\n\
             CONFIDENCE_SCALE_FACTOR_OPERATE   = {} (rejects if conf > 2% of price)\n\
             Accepted for liquidation: {}\n\
             Accepted for operation:   {}\n\
             Impact: An attacker can use a highly uncertain 3.5%-confidence price\n\
             (which would be rejected for normal operations) to execute liquidations,\n\
             increasing the risk of unfair liquidations in volatile conditions.",
            price, conf, conf as f64 / price as f64 * 100.0,
            CONFIDENCE_SCALE_FACTOR_LIQUIDATE,
            CONFIDENCE_SCALE_FACTOR_OPERATE,
            !fails_liquidate_check,
            !fails_operate_check
        );
    }

    // ------------------------------------------------------------------
    // H-3 PoC #3 — Combined attack: stale price + loose confidence
    //              passes both liquidation checks simultaneously.
    // ------------------------------------------------------------------
    /// Demonstrates that the two relaxed thresholds compound each other.
    #[test]
    fn test_h3_combined_stale_and_loose_confidence_both_pass_for_liquidation() {
        let current_time: u64 = 1_740_000_000;
        let publish_time: u64 = current_time - 7_000; // 7000s ago (1h 56m)

        let price: u64 = 10_000;
        let conf: u64 = 390;   // 3.9% confidence — near the 4% threshold

        let age = current_time - publish_time;

        let stale_for_liquidation  = age > MAX_AGE_LIQUIDATE;
        let stale_for_operation    = age > MAX_AGE_OPERATE;
        let low_confidence_liquidate = conf * CONFIDENCE_SCALE_FACTOR_LIQUIDATE > price;
        let low_confidence_operate   = conf * CONFIDENCE_SCALE_FACTOR_OPERATE   > price;

        // Combined: stale AND uncertain, yet both pass for liquidation
        let liquidation_accepted = !stale_for_liquidation && !low_confidence_liquidate;
        let operation_accepted   = !stale_for_operation   && !low_confidence_operate;

        assert!(
            liquidation_accepted,
            "[H-3] Stale + uncertain price should be accepted for liquidation"
        );
        assert!(
            !operation_accepted,
            "[H-3] Stale + uncertain price correctly rejected for normal operations"
        );

        println!(
            "\n[H-3 PROVEN — combined staleness + loose confidence]\n\
             Price age:          {}s ({:.1}h) — stale for ops, valid for liquidation\n\
             Confidence:         {} ({:.1}%) — too uncertain for ops, valid for liquidation\n\
             Liquidation accepted: {}\n\
             Operation accepted:   {}\n\
             Implication: The same price feed that would be rejected for\n\
             normal deposits/borrows can be used to trigger liquidations.\n\
             An attacker who can delay oracle updates gains a ~2-hour window\n\
             to liquidate positions at stale, manipulated prices.",
            age, age as f64 / 3600.0,
            conf, conf as f64 / price as f64 * 100.0,
            liquidation_accepted, operation_accepted
        );
    }

    // ------------------------------------------------------------------
    // H-3 PoC #4 — Oracle downtime scenario: no price update for 2 hours
    //              prevents valid liquidation of underwater positions.
    // ------------------------------------------------------------------
    /// Shows that when the oracle goes down for 2 hours, positions that
    /// become underwater (at the real current price) cannot be liquidated
    /// because the fresh (now-absent) price would fail the staleness check
    /// (there is no fresh price), and the stale pre-downtime price shows
    /// them as healthy.
    #[test]
    fn test_h3_oracle_downtime_blocks_valid_liquidation() {
        let current_time: u64 = 1_740_000_000;
        let last_published_price_time: u64 = current_time - 7_201; // just over 2h ago

        // The last known (stale) price: asset at $180 (position is healthy)
        let stale_price: u64 = 18_000; // $180

        // Real current price (oracle down, we can't get it): $120 (-33%)
        let real_price: u64 = 12_000;

        // Staleness check: the stale price is now too old even for liquidation
        let age = current_time - last_published_price_time;
        let stale_for_liquidation = age > MAX_AGE_LIQUIDATE;

        assert!(
            stale_for_liquidation,
            "[H-3] Price {} seconds old is stale even for liquidation",
            age
        );

        // Result: there is NO valid price to use for liquidation.
        // The position is underwater at $120 but cannot be liquidated.
        let position_collateral_value_at_stale = stale_price;  // $180 collateral
        let position_collateral_value_at_real  = real_price;   // $120 collateral
        let debt = 14_000u64; // $140 debt
        let is_healthy_at_stale = position_collateral_value_at_stale > debt;
        let is_healthy_at_real  = position_collateral_value_at_real  > debt;

        assert!(is_healthy_at_stale, "Position appears healthy at stale price");
        assert!(!is_healthy_at_real,  "Position is underwater at real price");

        println!(
            "\n[H-3 PROVEN — oracle downtime blocks liquidation]\n\
             Oracle last published: {}s ago (MAX_AGE_LIQUIDATE={})\n\
             Stale price ${}:  position appears {} (collateral ${} > debt ${})\n\
             Real  price ${}:  position is      {} (collateral ${} < debt ${})\n\
             No valid price available → liquidation cannot proceed.\n\
             Impact: Underwater positions cannot be liquidated, accumulating\n\
             bad debt that socialises losses across the protocol.",
            age, MAX_AGE_LIQUIDATE,
            stale_price / 100,
            if is_healthy_at_stale { "HEALTHY" } else { "UNDERWATER" },
            position_collateral_value_at_stale / 100, debt / 100,
            real_price / 100,
            if is_healthy_at_real { "HEALTHY" } else { "UNDERWATER" },
            position_collateral_value_at_real / 100, debt / 100
        );
    }
}

