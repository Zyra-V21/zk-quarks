//! Commitment schemes for Quarks
//!
//! Includes:
//! - Pedersen commitments (binding, hiding)
//! - Hyrax-style Inner Product Proofs (IPP) - paper Definition 3.17
//! - Bilinear Inner Product Proofs (BIPP) for Kopis-PC

pub mod pedersen;
pub mod bipp;
pub mod hyrax_ipp;

pub use pedersen::{PedersenParams, PedersenCommitment};
pub use hyrax_ipp::{
    HyraxIppParams, HyraxIppProof, HyraxIppProver, HyraxIppVerifier, 
    HyraxIppTranscript, HyraxIppInstance, HyraxIppWitness, inner_product,
};
pub use bipp::{BippParams, BippProof, BippProver, BippVerifier, BippTranscript};
