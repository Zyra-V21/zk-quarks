//! Complete zkSNARK protocols: Xiphos, Kopis, and Lakonia
//!
//! Integrates all components from §4-§8 of Quarks paper:
//! - Kopis-PC (§4): Constant-size polynomial commitments
//! - Grand Product SNARK (§5): Special-purpose SNARK
//! - Sparkle (§6): Sparse polynomial commitments
//! - Untrusted Assistant (§7): Accelerated preprocessing
//! - ZK Transformation (§8): Zero-knowledge sum-check

pub mod common;
pub mod utils;
pub mod kopis;
pub mod xiphos;
pub mod lakonia;

pub use common::{Proof, Witness, ComputationCommitment, GenericSnarkParams};
pub use kopis::KopisSnark;
pub use xiphos::XiphosSnark;
pub use lakonia::LakoniaSnark;

