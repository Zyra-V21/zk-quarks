//! Multilinear polynomial utilities and equality polynomials
//!
//! MLE definition (paper §3.3):
//! Z̃(x) = Σ Z(e) · ẽq(x, e), where x ∈ F^ℓ, e ∈ {0,1}^ℓ

pub mod multilinear;
pub mod eq;
pub mod sparse;

pub use multilinear::MultilinearPolynomial;
pub use eq::eq_polynomial;
pub use sparse::SparseMultilinearPolynomial;

