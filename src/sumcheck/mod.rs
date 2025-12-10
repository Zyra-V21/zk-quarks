//! Sum-check protocol for multilinear polynomials
//!
//! Reduces a claim Σ_{x∈{0,1}^ℓ} G(x) = T to G(r) = e, where r is random.
//!
//! Supports both interactive (prover/verifier) and non-interactive (NIZK via Fiat-Shamir).

mod prover;
mod verifier;
mod univariate;
pub mod transcript;

pub use prover::SumCheckProver;
pub use verifier::{SumCheckVerifier, RoundClaim};
pub use univariate::{UnivariateDegree1, UnivariateDegree2, UnivariateDegree3, UnivariatePolynomial};
pub use transcript::{Transcript, SumCheckProof};

