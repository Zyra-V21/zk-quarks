//! Finite field arithmetic module
//!
//! Provides wrappers and utilities for working with finite fields,
//! specifically BLS12-381 scalar field used in Quarks

pub mod bls12_381;

pub use ark_ff::{Field as ArkField, PrimeField};
pub use ark_bls12_381::Fr as Bls12381Fr;

/// Trait representing a finite field suitable for Quarks
pub trait QuarksField: ArkField + PrimeField {
    /// Field name for debugging
    fn field_name() -> &'static str;
    
    /// Generate a random field element
    fn random<R: rand::Rng>(rng: &mut R) -> Self;
}

