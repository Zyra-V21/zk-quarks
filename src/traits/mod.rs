//! Trait abstractions for Quarks zkSNARK components
//!
//! This module provides generic trait definitions that allow the SNARK
//! implementations to be parameterized over different backends (e.g., PCS schemes).
//!
//! # Design Philosophy
//!
//! Following Spartan2's design, we use Rust traits to abstract over:
//! - Polynomial Commitment Schemes (PCS)
//! - Future: Transcript engines, field types, etc.
//!
//! This enables:
//! - Swapping PCS backends without modifying SNARK logic
//! - Easy testing with mock implementations
//! - Comparative benchmarking across different schemes

pub mod pcs;

pub use pcs::PolynomialCommitmentScheme;

