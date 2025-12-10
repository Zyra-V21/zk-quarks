//! # Quarks: Quadruple-efficient transparent zkSNARKs
//!
//! Implementation of Xiphos and Kopis zkSNARKs from the paper:
//! "Quarks: Quadruple-efficient transparent zkSNARKs" (Lee & Setty, 2020)
//!
//! ## Structure
//!
//! - `field`: Finite field arithmetic
//! - `r1cs`: R1CS (Rank-1 Constraint System) representations
//! - `polynomial`: Multilinear polynomials and operations
//! - `sumcheck`: Sum-check protocol implementation
//! - `commitments`: Polynomial commitment schemes
//! - `kopis_pc`: Kopis-PC (constant-size commitments, O(√n) verification)
//! - `dory_pc`: Dory-PC (constant-size commitments, O(log n) verification)
//! - `grand_product`: Grand product SNARK
//! - `sparkle`: Sparkle compiler for sparse polynomials
//! - `zk`: Zero-knowledge transformations
//! - `assistant`: Untrusted assistant protocol
//! - `snark`: Complete SNARK implementations (Lakonia, Kopis, Xiphos)
//! - `traits`: Generic trait abstractions (PCS, etc.)
//!
//! ## Architecture
//!
//! SNARKs are generic over Polynomial Commitment Schemes (PCS):
//! ```ignore
//! let xiphos_dory = XiphosSnark::<DoryPCS>::setup(16);
//! let xiphos_kopis = XiphosSnark::<KopisPCS>::setup(16);
//! ```

pub mod field;
pub mod r1cs;
pub mod polynomial;
pub mod sumcheck;
pub mod commitments;
pub mod kopis_pc;
pub mod dory_pc;
pub mod grand_product;
pub mod sparkle;
pub mod zk;
pub mod assistant;
pub mod snark;
pub mod traits;

pub mod errors;
pub mod utils;

// Re-exports
pub use errors::{QuarksError, Result};
pub use traits::PolynomialCommitmentScheme;

// =============================================================================
// PCS Re-exports
// =============================================================================

/// Kopis-PC: O(1) commitment, O(√n) verification
pub use kopis_pc::KopisPCS;

/// Dory-PC: O(1) commitment, O(log n) verification
pub use dory_pc::DoryPCS;

// =============================================================================
// SNARK Type Aliases - Public API
// =============================================================================

/// Lakonia SNARK with Kopis-PC (O(√n) verification)
pub type Lakonia = snark::lakonia::GenericLakoniaSnark<KopisPCS>;

/// Lakonia SNARK with Dory-PC (O(log n) verification)
pub type LakoniaDory = snark::lakonia::GenericLakoniaSnark<DoryPCS>;

/// Kopis SNARK with Kopis-PC (O(√n) verification)
pub type Kopis = snark::kopis::KopisSnark<KopisPCS>;

/// Kopis SNARK with Dory-PC (O(log n) verification)
pub type KopisDory = snark::kopis::KopisSnark<DoryPCS>;

/// Xiphos SNARK with Dory-PC (O(log n) verification) - The "Quark"
pub type Xiphos = snark::xiphos::XiphosSnark<DoryPCS>;

/// Xiphos SNARK with Kopis-PC (O(√n) verification)
pub type XiphosKopis = snark::xiphos::XiphosSnark<KopisPCS>;

// =============================================================================
// Generic SNARK Re-exports
// =============================================================================

pub use snark::lakonia::GenericLakoniaSnark as LakoniaSnark;
pub use snark::kopis::KopisSnark;
pub use snark::xiphos::XiphosSnark;
pub use snark::common::{Witness, Proof, ComputationCommitment};
