//! Zero-Knowledge Transformation (§8 of Quarks paper)
//!
//! Implements the ZK sum-check protocol using low-weight polynomials.
//!
//! The key insight is that P masks F with a random polynomial G such that
//! F + G reveals nothing about F, but the sum-check still works.
//!
//! ## Low-weight polynomials
//!
//! g(X) = b₀·∏(1-Xᵢ) + Σᵢbᵢ(2Xᵢ-1)·∏_{j≠i}(1-Xⱼ)
//!
//! Support on Boolean hypercube: {(0,...,0), e₁,...,eℓ}

pub mod low_weight;
pub mod zk_sumcheck;

pub use low_weight::LowWeightPolynomial;
pub use zk_sumcheck::{ZkSumCheckProver, ZkSumCheckProof};

