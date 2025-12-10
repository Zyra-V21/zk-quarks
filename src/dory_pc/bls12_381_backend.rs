//! BLS12-381 backend for Dory-PC
//!
//! This module provides a complete BLS12-381 implementation of the Dory-PC
//! primitives, following the exact pattern of the BN254 arkworks backend.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

mod bls_field;
mod bls_group;
mod bls_pairing;
mod bls_poly;
mod bls_serde;
mod bls_transcript;

pub use bls_field::Bls381Fr;
pub use bls_group::{Bls381G1, Bls381G2, Bls381GT, G1Routines, G2Routines};
pub use bls_pairing::BLS12381;
pub use bls_poly::Bls381Polynomial;
pub use bls_transcript::Blake2bTranscript;
