//! Security Proof-of-Concept Tests
//!
//! This module contains executable PoC tests that prove the two critical
//! vulnerabilities identified in the Red Team audit:
//!
//! * [C-1] Admin PDA Initialization Front-Running — any wallet that calls
//!   `init_liquidity` (or its vault/oracle/flashloan equivalents) first
//!   before the legitimate deployer becomes the permanent authority of the
//!   entire protocol.
//!
//! * [C-2] Any `auth_user` Can Unpause a Deliberately-Paused Protocol —
//!   `change_status` uses the same `auth_users` set for both pause **and**
//!   unpause, so a compromised keeper key is sufficient to reverse an
//!   emergency governance pause.
//!
//! Each test is written in the same style as the existing Rust integration
//! tests (litesvm + the fluid-test-framework fixtures) so they can be run
//! with `cargo test -p tests security` and will produce a clear PASS/FAIL.

pub mod critical_c1_admin_frontrun;
pub mod critical_c2_auth_unpause;
