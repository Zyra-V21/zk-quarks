//! R1CS (Rank-1 Constraint System) representations and verification
//!
//! Definition (paper §3):
//! (A · z) ◦ (B · z) = (C · z) where z = (io, 1, w)

mod instance;
mod sparse_matrix;
mod witness;

pub use instance::R1CSInstance;
pub use sparse_matrix::SparseMatrix;
pub use witness::Witness;

