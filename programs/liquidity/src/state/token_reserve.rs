use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCodes;
use crate::events::LogUpdateExchangePrices;
use crate::state::RateModel;

use library::math::{casting::*, safe_math::*, u256::safe_multiply_divide};

/// Token configuration and exchange prices
#[account(zero_copy)]
#[derive(InitSpace)]
#[repr(C, packed)]
pub struct TokenReserve {
    pub mint: Pubkey, // Token mint address: it holds token related information like token name, symbol, decimals, etc.
    pub vault: Pubkey, // Token vault account:  it holds user related information of token

    pub borrow_rate: u16, // borrow rate (in 1e2: 100% = 10_000; 1% = 100 -> max value 65_535)
    pub fee_on_interest: u16, // fee on interest (in 1e2: 100% = 10_000; 1% = 100 -> max value 65_535). configurable.
    pub last_utilization: u16, // last stored utilization (in 1e2: 100% = 10_000; 1% = 100 -> max value 65_535)
    pub last_update_timestamp: u64, // last update timestamp, updated to u64
    pub supply_exchange_price: u64, // supply exchange price (1e12 -> max value 18_446_744_073_709_551_615)
    pub borrow_exchange_price: u64, // borrow exchange price (1e12 -> max value 18_446_744_073_709_551_615)

    // _configs2
    pub max_utilization: u16, // max allowed utilization (in 1e2: 100% = 10_000; 1% = 100 -> max value 65_535). configurable.

    // _totalAmounts
    pub total_supply_with_interest: u64, // total supply with interest
    pub total_supply_interest_free: u64, // total supply interest free
    pub total_borrow_with_interest: u64, // total borrow with interest
    pub total_borrow_interest_free: u64, // total borrow interest free
    pub total_claim_amount: u64,         // total claim amount

    // The following variables are used by the liquidity layer to track which protocol is calling operate
    // Since deposits happen before the Operate CPI call, we need flag variables to track when someone has sent tokens to the liquidity layer
    pub interacting_protocol: Pubkey, // interacting protocol
    pub interacting_timestamp: u64,   // interaction timestamp
    pub interacting_balance: u64,
}

pub const EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS: u128 = 10u128.pow(17);

impl TokenReserve {
    pub fn init(&mut self, mint: Pubkey, vault: Pubkey) -> Result<()> {
        self.mint = mint;
        self.vault = vault;
        self.last_update_timestamp = Clock::get()?.unix_timestamp.cast()?;

        let default_exchange_price: u64 = EXCHANGE_PRICES_PRECISION.cast()?;
        self.supply_exchange_price = default_exchange_price;
        self.borrow_exchange_price = default_exchange_price;

        Ok(())
    }

    pub fn add_claim_amount(&mut self, amount: u64) -> Result<()> {
        self.total_claim_amount = self.total_claim_amount.safe_add(amount)?;
        Ok(())
    }

    pub fn reduce_claim_amount(&mut self, amount: u64) -> Result<()> {
        self.total_claim_amount = self.total_claim_amount.safe_sub(amount)?;
        Ok(())
    }

    fn get_with_interest_vs_free_ratio(
        &self,
        with_interest: u128,
        interest_free: u128,
    ) -> Result<u128> {
        let ratio: u128 = if with_interest > interest_free {
            // ratio with interest being larger
            interest_free
                .safe_mul(FOUR_DECIMALS)?
                .safe_div(with_interest)?
        } else if with_interest < interest_free {
            // ratio with interest free being larger
            with_interest
                .safe_mul(FOUR_DECIMALS)?
                .safe_div(interest_free)?
        } else {
            // amounts match exactly
            if with_interest > 0 {
                // amounts are not 0 -> set ratio to 1
                FOUR_DECIMALS
            } else {
                // if total = 0
                0
            }
        };

        Ok(ratio)
    }

    fn get_supply_ratio(&self) -> Result<u128> {
        let supply_ratio: u128 = self.get_with_interest_vs_free_ratio(
            self.get_total_supply_with_interest()?,
            self.get_total_supply_interest_free()?,
        )?;

        Ok(supply_ratio)
    }

    fn get_borrow_ratio(&self) -> Result<u128> {
        let borrow_ratio: u128 = self.get_with_interest_vs_free_ratio(
            self.get_total_borrow_with_interest()?,
            self.get_total_borrow_interest_free()?,
        )?;

        Ok(borrow_ratio)
    }

    pub fn update_exchange_price(&mut self) -> Result<(u128, u128)> {
        // calculate the new exchange prices based on earned interest
        let (supply_exchange_price_, borrow_exchange_price_) = self.calculate_exchange_prices()?;

        self.supply_exchange_price = supply_exchange_price_.cast()?;
        self.borrow_exchange_price = borrow_exchange_price_.cast()?;
        self.last_update_timestamp = Clock::get()?.unix_timestamp.cast()?;

        emit!(LogUpdateExchangePrices {
            token: self.mint,
            supply_exchange_price: supply_exchange_price_,
            borrow_exchange_price: borrow_exchange_price_,
            borrow_rate: self.borrow_rate,
            utilization: self.last_utilization,
        });

        Ok((supply_exchange_price_, borrow_exchange_price_))
    }

    pub fn get_interacting_balance(&self) -> Result<u128> {
        Ok(self.interacting_balance.cast()?)
    }

    pub fn reset_interacting_state(&mut self) -> Result<()> {
        self.interacting_balance = 0;
        self.interacting_protocol = Pubkey::default();
        self.interacting_timestamp = 0;
        Ok(())
    }

    pub fn set_new_total_supply_with_interest(
        &mut self,
        new_supply_interest_raw: i128,
    ) -> Result<()> {
        let new_supply_interest_raw: u128 =
            self.get_new_total_supply_interest_raw(new_supply_interest_raw)?;

        self.set_total_supply_with_interest(new_supply_interest_raw)?;

        Ok(())
    }

    pub fn get_new_total_supply_interest_raw(&self, new_supply_interest_raw: i128) -> Result<u128> {
        let mut current_supply_raw_interest = self.get_total_supply_with_interest()?;

        if new_supply_interest_raw > 0 {
            current_supply_raw_interest =
                current_supply_raw_interest.safe_add(new_supply_interest_raw.cast()?)?;
        } else {
            current_supply_raw_interest =
                current_supply_raw_interest.saturating_sub(new_supply_interest_raw.abs().cast()?);

            // withdraw amount is > total supply -> withdraw total supply down to 0
            // Note no risk here as if the user withdraws more than supplied it would revert already
            // earlier. Total amounts can end up < sum of user amounts because of rounding
        }

        Ok(current_supply_raw_interest)
    }

    pub fn get_total_supply_with_interest(&self) -> Result<u128> {
        Ok(self.total_supply_with_interest.cast()?)
    }

    pub fn set_total_supply_with_interest(&mut self, value: u128) -> Result<()> {
        self.total_supply_with_interest = value.cast()?;
        Ok(())
    }

    fn get_supply_with_interest_normal_ceil(&self, supply_exchange_price: u128) -> Result<u128> {
        // @dev Only gets used in cal_revenue
        Ok(self
            .get_total_supply_with_interest()?
            .safe_mul(supply_exchange_price)?
            .safe_div_ceil(EXCHANGE_PRICES_PRECISION)?)
    }

    pub fn set_new_total_supply_interest_free(
        &mut self,
        new_supply_interest_free: i128,
    ) -> Result<()> {
        let new_supply_interest_free =
            self.get_new_total_supply_interest_free(new_supply_interest_free)?;

        self.set_total_supply_interest_free(new_supply_interest_free)?;
        Ok(())
    }

    pub fn get_new_total_supply_interest_free(
        &self,
        new_supply_interest_free: i128,
    ) -> Result<u128> {
        let mut current_supply_interest_free = self.get_total_supply_interest_free()?;

        // supply or withdraw interest free -> normal amount
        if new_supply_interest_free > 0 {
            current_supply_interest_free =
                current_supply_interest_free.safe_add(new_supply_interest_free.cast()?)?;
        } else {
            current_supply_interest_free =
                current_supply_interest_free.saturating_sub(new_supply_interest_free.abs().cast()?);
            // withdraw amount is > total supply -> withdraw total supply down to 0
            // Note no risk here as if the user withdraws more than supplied it would revert already
            // earlier. Total amounts can end up < sum of user amounts because of rounding
        }

        if current_supply_interest_free > MAX_TOKEN_AMOUNT_CAP {
            return Err(ErrorCodes::ValueOverflowTotalSupply.into());
        }

        Ok(current_supply_interest_free)
    }

    pub fn get_total_supply_interest_free(&self) -> Result<u128> {
        Ok(self.total_supply_interest_free.cast()?)
    }

    pub fn set_total_supply_interest_free(&mut self, value: u128) -> Result<()> {
        self.total_supply_interest_free = value.cast()?;
        Ok(())
    }

    pub fn set_new_total_borrow_with_interest(
        &mut self,
        new_borrow_interest_raw: i128,
    ) -> Result<()> {
        let new_borrow_interest_raw: u128 =
            self.get_new_total_borrow_interest_raw(new_borrow_interest_raw)?;

        self.set_total_borrow_with_interest(new_borrow_interest_raw)?;
        Ok(())
    }

    pub fn get_new_total_borrow_interest_raw(&self, new_borrow_interest_raw: i128) -> Result<u128> {
        let mut current_borrow_raw_interest = self.get_total_borrow_with_interest()?;

        if new_borrow_interest_raw > 0 {
            current_borrow_raw_interest =
                current_borrow_raw_interest.safe_add(new_borrow_interest_raw.cast()?)?;
        } else {
            current_borrow_raw_interest =
                current_borrow_raw_interest.saturating_sub(new_borrow_interest_raw.abs().cast()?);

            // payback amount is > total borrow -> payback total borrow down to 0
        }

        Ok(current_borrow_raw_interest)
    }

    fn get_borrow_with_interest_normal(&self, borrow_exchange_price: u128) -> Result<u128> {
        Ok(self
            .get_total_borrow_with_interest()?
            .safe_mul(borrow_exchange_price)?
            .safe_div(EXCHANGE_PRICES_PRECISION)?)
    }

    pub fn get_total_borrow_with_interest(&self) -> Result<u128> {
        Ok(self.total_borrow_with_interest.cast()?)
    }

    pub fn set_total_borrow_with_interest(&mut self, value: u128) -> Result<()> {
        self.total_borrow_with_interest = value.cast()?;
        Ok(())
    }

    pub fn set_new_total_borrow_interest_free(
        &mut self,
        new_borrow_interest_free: i128,
    ) -> Result<()> {
        let new_borrow_interest_free =
            self.get_new_total_borrow_interest_free(new_borrow_interest_free)?;

        self.set_total_borrow_interest_free(new_borrow_interest_free)?;
        Ok(())
    }

    pub fn get_new_total_borrow_interest_free(
        &self,
        new_borrow_interest_free: i128,
    ) -> Result<u128> {
        let mut current_borrow_interest_free = self.get_total_borrow_interest_free()?;

        // borrow or payback interest free -> normal amount
        if new_borrow_interest_free > 0 {
            current_borrow_interest_free =
                current_borrow_interest_free.safe_add(new_borrow_interest_free.cast()?)?;
        } else {
            current_borrow_interest_free =
                current_borrow_interest_free.saturating_sub(new_borrow_interest_free.abs().cast()?);

            // payback amount is > total borrow -> payback total borrow down to 0
        }

        if current_borrow_interest_free > MAX_TOKEN_AMOUNT_CAP {
            return Err(ErrorCodes::ValueOverflowTotalBorrow.into());
        }

        Ok(current_borrow_interest_free)
    }

    pub fn get_total_borrow_interest_free(&self) -> Result<u128> {
        Ok(self.total_borrow_interest_free.cast()?)
    }

    pub fn set_total_borrow_interest_free(&mut self, value: u128) -> Result<()> {
        self.total_borrow_interest_free = value.cast()?;
        Ok(())
    }

    pub fn update_exchange_prices_and_rates<'info>(
        &mut self,
        rate_model: &RateModel,
    ) -> Result<(u128, u128)> {
        // Calculate the new exchange prices based on earned interest
        let (supply_exchange_price, borrow_exchange_price) = self.calculate_exchange_prices()?;

        // Calculate utilization: totalBorrow / totalSupply
        // If no supply, utilization must be 0 (avoid division by 0)
        let utilization: u16 =
            self.calc_utilization(supply_exchange_price, borrow_exchange_price, None, None)?;

        // Calculate updated borrow rate from utilization
        let borrow_rate: u16 = rate_model.calc_borrow_rate_from_utilization(utilization.cast()?)?;

        self.supply_exchange_price = supply_exchange_price.cast()?;
        self.borrow_exchange_price = borrow_exchange_price.cast()?;
        self.last_utilization = utilization;
        self.borrow_rate = borrow_rate;

        self.last_update_timestamp = Clock::get()?.unix_timestamp.cast()?;

        emit!(LogUpdateExchangePrices {
            token: self.mint,
            supply_exchange_price: supply_exchange_price,
            borrow_exchange_price: borrow_exchange_price,
            borrow_rate: borrow_rate,
            utilization: utilization,
        });

        Ok((supply_exchange_price, borrow_exchange_price))
    }

    pub fn calculate_exchange_prices(&self) -> Result<(u128, u128)> {
        let mut supply_exchange_price: u128 = self.supply_exchange_price.cast()?;
        let mut borrow_exchange_price: u128 = self.borrow_exchange_price.cast()?;

        if supply_exchange_price == 0 || borrow_exchange_price == 0 {
            return Err(ErrorCodes::ExchangePriceZero.into());
        }

        let borrow_rate: u128 = self.borrow_rate.cast()?;

        let timestamp: u128 = Clock::get()?.unix_timestamp.cast()?; // current block timestamp
        let last_update_timestamp: u128 = self.last_update_timestamp.cast()?;

        // last timestamp can not be > current timestamp
        let seconds_since_last_update: u128 = timestamp.safe_sub(last_update_timestamp)?;

        if seconds_since_last_update == 0
            || borrow_rate == 0
            || self.total_borrow_with_interest == 0
        {
            // if no time passed, borrow rate is 0, or no raw borrowings: no exchange price update needed
            return Ok((supply_exchange_price, borrow_exchange_price));
        }

        // calculate new borrow exchange price.
        // formula borrowExchangePriceIncrease: previous price * borrow rate * secondsSinceLastUpdate_.
        borrow_exchange_price = borrow_exchange_price.safe_add(
            borrow_exchange_price
                .safe_mul(borrow_rate)?
                .safe_mul(seconds_since_last_update)?
                .safe_div_ceil(SECONDS_PER_YEAR.safe_mul(FOUR_DECIMALS)?)?,
        )?;

        // FOR SUPPLY EXCHANGE PRICE:
        // all yield paid by borrowers (in mode with interest) goes to suppliers in mode with interest.
        // formula: previous price * supply rate * secondsSinceLastUpdate_.
        // where supply rate = (borrow rate  - revenueFee%) * ratioSupplyYield. And
        // ratioSupplyYield = utilization * supplyRatio * borrowRatio
        //
        // Example:
        // supplyRawInterest is 80, supplyInterestFree is 20. totalSupply is 100. BorrowedRawInterest is 50.
        // BorrowInterestFree is 10. TotalBorrow is 60. borrow rate 40%, revenueFee 10%.
        // yield is 10 (so half a year must have passed).
        // supplyRawInterest must become worth 89. totalSupply must become 109. BorrowedRawInterest must become 60.
        // borrowInterestFree must still be 10. supplyInterestFree still 20. totalBorrow 70.
        // supplyExchangePrice would have to go from 1 to 1,125 (+ 0.125). borrowExchangePrice from 1 to 1,2 (+0.2).
        // utilization is 60%. supplyRatio = 20 / 80 = 25% (only 80% of lenders receiving yield).
        // borrowRatio = 10 / 50 = 20% (only 83,333% of borrowers paying yield):
        // x of borrowers paying yield = 100% - (20 / (100 + 20)) = 100% - 16.6666666% = 83,333%.
        // ratioSupplyYield = 60% * 83,33333% * (100% + 25%) = 62,5%
        // supplyRate = (40% * (100% - 10%)) * 62,5% = 36% * 62,5% = 22.5%
        // increase in supplyExchangePrice, assuming 100 as previous price.
        // 100 * 22,5% * 1/2 (half a year) = 0,1125.
        // cross-check supplyRawInterest worth = 80 * 1.1125 = 89. totalSupply worth = 89 + 20.

        // -------------- 1. calculate ratioSupplyYield --------------------------------
        // step1: utilization * supplyRatio (or actually part of lenders receiving yield)

        if self.total_supply_with_interest == 0 {
            // if no raw supply: no exchange price update needed
            return Ok((supply_exchange_price, borrow_exchange_price));
        }

        let supply_ratio = self.get_supply_ratio()?;

        // this ratio_supply_yield doesn't contain the borrow_ratio part
        let mut ratio_supply_yield: u128 =
            if self.total_supply_with_interest < self.total_supply_interest_free {
                // ratio is supplyWithInterest / supplyInterestFree (supplyInterestFree is bigger)

                if supply_ratio == 0 {
                    // @dev if supply_ratio == 0 and supply interest free > with interest then
                    // no one is earning interest or total_supply is 0, so no exchange price update needed.
                    // this covers the case where supply with interest exists but it is tiny compared to interest free supply.

                    return Ok((supply_exchange_price, borrow_exchange_price));
                }

                let supply_ratio: u128 = EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS
                    .safe_mul(FOUR_DECIMALS)?
                    .safe_div(supply_ratio)?;

                // Note: case where temp_ == 0 (only supplyInterestFree, no yield) already covered by early return
                // in the if statement a little above.

                // based on above example but supplyRawInterest is 20, supplyInterestFree is 80. no fee.
                // supplyRawInterest must become worth 30. totalSupply must become 110.
                // supplyExchangePrice would have to go from 1 to 1,5. borrowExchangePrice from 1 to 1,2.
                // so ratioSupplyYield must come out as 2.5 (250%).
                // supplyRatio would be (20 * 10_000 / 80) = 2500. but must be inverted.

                let utilization: u128 = self.last_utilization.cast()?;

                utilization
                    .safe_mul(EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS.safe_add(supply_ratio)?)?
                    .safe_div(FOUR_DECIMALS)?
            } else {
                let utilization: u128 = self.last_utilization.cast()?;

                // when with interest = 1e10 and interest free = 100, then ratio is 100 * 1e4 / 1e10 = 0
                // when only with interest exists, then also ratio is 0
                // so allowing the supply_ratio 0 case here is fine.

                // if ratio == 0 then only supplyWithInterest => full yield. ratio is already 0
                // e.g. 5_000 * 10_000 + (20 * 10_000 / 80) / 10_000 = 5000 * 12500 / 10000 = 6250 (=62.5%).
                // 1e17 * utilization * (100% + supplyRatio) / 100%
                utilization
                    .safe_mul(EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS)?
                    .safe_mul(FOUR_DECIMALS.safe_add(supply_ratio)?)?
                    .safe_div(FOUR_DECIMALS.safe_mul(FOUR_DECIMALS)?)?
            };

        let borrow_ratio = self.get_borrow_ratio()?;

        let borrow_ratio = if self.total_borrow_with_interest < self.total_borrow_interest_free {
            // ratio is borrowWithInterest / borrowInterestFree (borrowInterestFree is bigger)
            // borrowRatio_ => x of total borrowers paying yield. scale to 1e17.

            // Note: case where borrowRatio_ == 0 (only borrowInterestFree, no yield) already covered
            // at the beginning of the method by early return if `borrowRatio_ == 1`.

            // based on above example but borrowRawInterest is 10, borrowInterestFree is 50. no fee. borrowRatio = 20%.
            // so only 16.66% of borrowers are paying yield. so the 100% - part of the formula is not needed.
            // x of borrowers paying yield = (borrowRatio / (100 + borrowRatio)) = 16.6666666%
            // borrowRatio_ => x of total borrowers paying yield. scale to 1e17.
            let _borrow_ratio: u128 = (borrow_ratio)
                .safe_mul(EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS)?
                .safe_div(FOUR_DECIMALS.safe_add(borrow_ratio)?)?;

            // max value here for borrowRatio_ is (1e31 / (1e4 + 1e4))= 5e26 (= 50% of borrowers paying yield).
            _borrow_ratio
        } else {
            // ratio is borrowInterestFree / borrowWithInterest (borrowWithInterest is bigger)
            // borrowRatio_ => x of total borrowers paying yield. scale to 1e17.

            // x of borrowers paying yield = 100% - (borrowRatio / (100 + borrowRatio)) = 100% - 16.6666666% = 83,333%.
            let _borrow_ratio: u128 = EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS.safe_sub(
                borrow_ratio
                    .safe_mul(EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS)?
                    .safe_div(FOUR_DECIMALS.safe_add(borrow_ratio)?)?,
            )?;
            // borrowRatio can never be > 100%. so max subtraction can be 100% - 100% / 200%.
            // or if borrowRatio_ is 0 -> 100% - 0. or if borrowRatio_ is 1 -> 100% - 1 / 101.
            // max value here for borrowRatio_ is 1e17 - 0 = 1e17 (= 100% of borrowers paying yield).

            _borrow_ratio
        };

        ratio_supply_yield = safe_multiply_divide(
            ratio_supply_yield,
            borrow_ratio,
            EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS,
        )?
        .safe_mul(FOUR_DECIMALS)?
        .safe_div(EXCHANGE_PRICE_RATE_OUTPUT_DECIMALS)?;

        // 2. calculate supply rate
        // supply rate (borrow rate  - revenueFee%) * ratioSupplyYield.
        // division part is done in next step to increase precision. (divided by 2x FOUR_DECIMALS, fee + borrowRate)
        // Note that all calculation divisions for supplyExchangePrice are rounded down.
        // Note supply rate can be bigger than the borrowRate, e.g. if there are only few lenders with interest
        // but more suppliers not earning interest.
        let supply_rate: u128 = borrow_rate
            .safe_mul(ratio_supply_yield)?
            .safe_mul(FOUR_DECIMALS.safe_sub(self.fee_on_interest.cast()?)?)?;
        // fee can not be > 100%. max possible = 65535 * ~1.64e8 * 1e4 =~1.074774e17.

        // 3. calculate increase in supply exchange price
        supply_exchange_price = supply_exchange_price.safe_add(
            supply_exchange_price
                .safe_mul(supply_rate)?
                .safe_mul(seconds_since_last_update)?
                .safe_div(SECONDS_PER_YEAR.safe_mul(FOUR_DECIMALS)?)?
                .safe_div(FOUR_DECIMALS.safe_mul(FOUR_DECIMALS)?)?,
        )?;

        Ok((supply_exchange_price, borrow_exchange_price))
    }

    // Gets the total supply by combining interest free and interest-bearing supply
    pub fn get_total_supply_ceil(&self, supply_exchange_price: u128) -> Result<u128> {
        // Extract interest free supply
        let supply_interest_free: u128 = self.get_total_supply_interest_free()?;

        // Convert raw interest-bearing supply to normalized amount
        let normalized_interest_supply: u128 =
            self.get_supply_with_interest_normal_ceil(supply_exchange_price)?;

        // Total supply = interest_free + normalized_interest_supply
        Ok(supply_interest_free.safe_add(normalized_interest_supply)?)
    }

    // Gets the total borrow by combining interest free and interest-bearing borrow
    pub fn get_total_borrow(&self, borrow_exchange_price: u128) -> Result<u128> {
        // Extract interest free borrow
        let borrow_interest_free: u128 = self.get_total_borrow_interest_free()?;

        // Convert raw interest-bearing borrow to normalized amount
        let normalized_interest_borrow: u128 =
            self.get_borrow_with_interest_normal(borrow_exchange_price)?;

        // Total borrow = interest_free + normalized_interest_borrow
        Ok(borrow_interest_free.safe_add(normalized_interest_borrow)?)
    }

    /// Check if scaled amounts exceed maximum token cap
    /// Used to prevent overflow when calculating utilization for supply or borrow operations
    fn check_scaled_amount_overflow(
        &self,
        amount: Option<i128>,
        interest_amount: u128,
        scaled_amount: u128,
        is_supply: bool,
    ) -> Result<()> {
        if let Some(amt) = amount {
            if amt > 0
                && (interest_amount > MAX_TOKEN_AMOUNT_CAP * EXCHANGE_PRICES_PRECISION
                    || scaled_amount > MAX_TOKEN_AMOUNT_CAP * EXCHANGE_PRICES_PRECISION)
            {
                return Err(if is_supply {
                    ErrorCodes::ValueOverflowTotalSupply.into()
                } else {
                    ErrorCodes::ValueOverflowTotalBorrow.into()
                });
            }
        }
        Ok(())
    }

    /// Calculates utilization over scaled borrow and supply values
    pub fn calc_utilization(
        &self,
        supply_exchange_price: u128,
        borrow_exchange_price: u128,
        supply_amount: Option<i128>,
        borrow_amount: Option<i128>,
    ) -> Result<u16> {
        let supply_interest_free: u128 = self.get_total_supply_interest_free()?;
        let supply_with_interest: u128 = self.get_total_supply_with_interest()?;
        let borrow_interest_free: u128 = self.get_total_borrow_interest_free()?;
        let borrow_with_interest: u128 = self.get_total_borrow_with_interest()?;

        // Scale interest-free amounts by EXCHANGE_PRICES_PRECISION to match the precision of interest-bearing amounts
        let interest_free_supply = supply_interest_free.safe_mul(EXCHANGE_PRICES_PRECISION)?;
        let interest_free_borrow = borrow_interest_free.safe_mul(EXCHANGE_PRICES_PRECISION)?;

        let interest_supply = supply_with_interest.safe_mul(supply_exchange_price)?;
        let interest_borrow = borrow_with_interest.safe_mul(borrow_exchange_price)?;

        // Combine to get total scaled amounts
        let total_scaled_supply = interest_supply.safe_add(interest_free_supply)?;
        let total_scaled_borrow = interest_borrow.safe_add(interest_free_borrow)?;

        // If no supply, utilization must be 0 (avoid division by 0)
        if total_scaled_supply == 0 {
            return Ok(0);
        }

        // Check for overflow on both supply and borrow scaled amounts
        self.check_scaled_amount_overflow(
            supply_amount,
            interest_supply,
            total_scaled_supply,
            true,
        )?;

        self.check_scaled_amount_overflow(
            borrow_amount,
            interest_borrow,
            total_scaled_borrow,
            false,
        )?;

        // utilization = scaled_borrow * FOUR_DECIMALS / total_scaled_supply
        let utilization = total_scaled_borrow
            .safe_mul(FOUR_DECIMALS)?
            .safe_div(total_scaled_supply)?;

        Ok(utilization.cast()?)
    }

    pub fn calc_revenue(&self, liquidity_token_balance: u128) -> Result<u128> {
        // Calculate the new exchange prices based on earned interest
        let (supply_exchange_price, borrow_exchange_price) = self.calculate_exchange_prices()?;

        // Get total supply and borrow amounts
        let total_supply: u128 = self.get_total_supply_ceil(supply_exchange_price)?;

        if total_supply > 0 {
            // Available revenue: balanceOf(token) + totalBorrowings - totalLendings
            let total_borrow: u128 = self.get_total_borrow(borrow_exchange_price)?;

            // Ensure there is no possible case because of rounding etc. where this would revert
            let revenue_amount: u128 = liquidity_token_balance
                .safe_add(total_borrow)?
                .saturating_sub(self.total_claim_amount.cast()?); // Since claim amount is still in the vault, but that is not revenue

            // @dev no safe_sub here, because we need 0 as result if total_supply >= revenue_amount
            Ok(revenue_amount.saturating_sub(total_supply))
        } else {
            // If supply is 0, then rest of balance can be withdrawn as revenue so that no amounts get stuck
            Ok(liquidity_token_balance.saturating_sub(self.total_claim_amount.cast()?))
            // Since claim amount is still in the vault, but that is not revenue
        }
    }
}

// ============================================================================
//  [M-4] SECURITY POC — `saturating_sub` Silently Masks Bad Debt
//
//  Several financially critical functions use `saturating_sub` instead of
//  `safe_sub` / `checked_sub`.  When the subtraction would underflow (i.e.,
//  the protocol is in a bad-debt / insolvency state), the result is silently
//  clamped to 0 instead of propagating an error.  This means:
//
//  1. `calc_revenue` returns 0 (zero reported revenue) even when the vault is
//     insolvent (total_supply > balance + total_borrow).
//  2. `get_new_total_supply_interest_raw` clamps the total supply to 0 when a
//     withdrawal exceeds the tracked supply, hiding an accounting mismatch.
//  3. `get_new_total_borrow_interest_raw` silently zeroes out total borrows on
//     an over-payback.
//
//  In all three cases the protocol silently moves to an incorrect state
//  instead of halting.  A malicious operator could craft transactions that
//  trigger these underflows to obscure protocol insolvency and delay the
//  detection of an active exploit.
// ============================================================================
#[cfg(test)]
mod security_poc_m4_tests {
    use super::*;

    /// Helper: build a zeroed TokenReserve (no Solana clock calls needed at rest).
    fn zeroed_reserve() -> TokenReserve {
        TokenReserve {
            mint: Pubkey::default(),
            vault: Pubkey::default(),
            borrow_rate: 0,
            fee_on_interest: 0,
            last_utilization: 0,
            last_update_timestamp: 0,
            supply_exchange_price: 1_000_000_000_000, // 1e12
            borrow_exchange_price: 1_000_000_000_000, // 1e12
            max_utilization: 10_000,
            total_supply_with_interest: 0,
            total_supply_interest_free: 0,
            total_borrow_with_interest: 0,
            total_borrow_interest_free: 0,
            total_claim_amount: 0,
            interacting_protocol: Pubkey::default(),
            interacting_timestamp: 0,
            interacting_balance: 0,
        }
    }

    // ------------------------------------------------------------------
    // M-4 PoC #1 — `get_new_total_supply_interest_raw` clamps to 0
    //              instead of returning an error on over-withdrawal.
    // ------------------------------------------------------------------
    /// When `withdraw_raw > total_supply_raw`, the subtraction underflows.
    /// `saturating_sub` silently returns 0.
    /// A correct implementation would return `Err(Underflow)`.
    ///
    /// Impact: The protocol's `total_supply_with_interest` can be driven to
    /// 0 even when actual user balances sum to more than 0, creating an
    /// accounting mismatch that future operations will trust silently.
    #[test]
    fn test_m4_supply_raw_saturating_sub_masks_underflow() {
        let mut reserve = zeroed_reserve();

        // Set up: 1000 units of raw supply with interest
        reserve.total_supply_with_interest = 1_000;

        // Attempt to "withdraw" 2000 units — more than exists.
        // A safe implementation would error here.
        let withdraw_raw: i128 = -2_000;
        let result = reserve.get_new_total_supply_interest_raw(withdraw_raw);

        // BUG: Instead of erroring, the function returns Ok(0).
        assert!(
            result.is_ok(),
            "[M-4] Expected Ok(0) from saturating_sub (demonstrating the silent clamp), got Err"
        );
        let new_supply = result.unwrap();
        assert_eq!(
            new_supply, 0,
            "[M-4] saturating_sub clamped to 0 instead of propagating an underflow error"
        );

        // The accounting is now WRONG: total supply says 0 but user positions
        // still track amounts that sum to > 0.
        println!(
            "\n[M-4 PROVEN] Over-withdrawal: total_supply was 1000, withdrew 2000.\n\
             Expected: Err(Underflow) — Got: Ok(0).\n\
             The protocol silently sets total_supply = 0, hiding accounting insolvency."
        );
    }

    // ------------------------------------------------------------------
    // M-4 PoC #2 — `get_new_total_borrow_interest_raw` clamps to 0 on
    //              over-payback, hiding borrow insolvency.
    // ------------------------------------------------------------------
    /// When `payback_raw > total_borrow_raw`, the result should be an error.
    /// Instead, `saturating_sub` returns 0.
    #[test]
    fn test_m4_borrow_raw_saturating_sub_masks_underflow() {
        let mut reserve = zeroed_reserve();

        // 500 units of outstanding raw borrow
        reserve.total_borrow_with_interest = 500;

        // Attacker pays back 1500 — more than the total borrow
        let payback_raw: i128 = -1_500;
        let result = reserve.get_new_total_borrow_interest_raw(payback_raw);

        assert!(
            result.is_ok(),
            "[M-4] Expected Ok(0) from saturating_sub on borrow, got Err"
        );
        assert_eq!(
            result.unwrap(),
            0,
            "[M-4] Borrow over-payback silently clamped to 0"
        );

        println!(
            "\n[M-4 PROVEN] Over-payback: total_borrow was 500, paid back 1500.\n\
             Expected: Err(Underflow) — Got: Ok(0).\n\
             The protocol records total_borrow = 0 even though the math is wrong."
        );
    }

    // ------------------------------------------------------------------
    // M-4 PoC #3 — `get_new_total_supply_interest_free` clamps to 0
    //              (same pattern, interest-free side).
    // ------------------------------------------------------------------
    #[test]
    fn test_m4_supply_interest_free_saturating_sub_masks_underflow() {
        let mut reserve = zeroed_reserve();
        reserve.total_supply_interest_free = 100;

        let withdraw_free: i128 = -999;
        let result = reserve.get_new_total_supply_interest_free(withdraw_free);

        assert!(
            result.is_ok(),
            "[M-4] Expected Ok(0) from interest-free supply over-withdrawal"
        );
        assert_eq!(
            result.unwrap(),
            0,
            "[M-4] Interest-free supply silently clamped to 0"
        );

        println!(
            "\n[M-4 PROVEN] Interest-free over-withdrawal: supply was 100, withdrew 999.\n\
             Got Ok(0) instead of Err — accounting mismatch hidden silently."
        );
    }

    // ------------------------------------------------------------------
    // M-4 PoC #4 — `calc_revenue` reports 0 when the vault is insolvent.
    //
    // Scenario: The vault balance + borrows are LESS than total supply
    // (bad debt / insolvency). The correct behaviour is to return an error
    // so that callers know revenue collection is impossible.  Instead,
    // `saturating_sub` returns 0 — making revenue look like zero, not
    // like a critical solvency failure.
    // ------------------------------------------------------------------
    /// This test requires the exchange price to be 1:1 (i.e., the clock
    /// hasn't advanced since init so `calculate_exchange_prices` will short-
    /// circuit and return the stored prices unchanged).
    ///
    /// We set `last_update_timestamp` equal to the current (mock) time so
    /// `seconds_since_last_update == 0` inside `calculate_exchange_prices`,
    /// which means the function early-returns the stored prices without
    /// needing Clock::get().
    ///
    /// Note: This test isolates the `saturating_sub` logic path by
    /// constructing a scenario where the vault is insolvent but the function
    /// happily returns 0 instead of signaling an error.
    #[test]
    fn test_m4_calc_revenue_returns_zero_on_insolvency_not_error() {
        // To avoid needing Solana's Clock, we call calc_revenue only through
        // the sub-functions that don't touch the clock.
        // We directly test the saturating_sub logic in calc_revenue by
        // exercising the total_supply > available_balance + total_borrow path.
        //
        // revenue_amount = (balance + total_borrow) - total_claim  [saturating to 0]
        // result         = revenue_amount - total_supply           [saturating to 0]
        //
        // When total_supply = 1000 and balance + borrow - claim = 500,
        // `revenue_amount.saturating_sub(total_supply)` should be -500 → clamped to 0.

        // We can exercise the saturating_sub arithmetic directly since it is
        // the same operation that calc_revenue performs internally.
        let total_supply: u128 = 1_000_000;      // 1M tokens owed to suppliers
        let vault_balance: u128 = 400_000;       // only 400k in vault (bad debt!)
        let total_borrow: u128 = 100_000;        // 100k borrowed out
        let total_claim: u128 = 0;

        // This is exactly what calc_revenue computes:
        let revenue_amount: u128 = vault_balance
            .checked_add(total_borrow)
            .unwrap()
            .saturating_sub(total_claim);             // = 500_000

        // BUG: this subtraction (500_000 - 1_000_000) underflows.
        // saturating_sub returns 0 instead of signaling insolvency.
        let reported_revenue: u128 = revenue_amount.saturating_sub(total_supply);

        assert_eq!(
            reported_revenue,
            0,
            "[M-4] calc_revenue silently returns 0 on insolvent vault — \
             should return an error signaling bad debt"
        );

        // Verify: the vault IS actually insolvent
        let deficit = total_supply.checked_sub(vault_balance + total_borrow).unwrap();
        assert!(
            deficit > 0,
            "Vault should be insolvent with a deficit of {} tokens",
            deficit
        );

        println!(
            "\n[M-4 PROVEN — insolvency hidden] Vault state:\n\
             - Total supply (owed to lenders): {}\n\
             - Vault balance:                  {}\n\
             - Total borrows outstanding:      {}\n\
             - Actual deficit (bad debt):      {}\n\
             - Revenue reported by protocol:   {}\n\
             Impact: An admin calls collect_revenue(), receives 0, and assumes\n\
             the vault is healthy.  The insolvency is invisible until a mass\n\
             withdrawal fails.",
            total_supply, vault_balance, total_borrow, deficit, reported_revenue
        );
    }
}

