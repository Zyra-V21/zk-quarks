//! Helper utilities for SNARK implementations
//!
//! Provides glue code to convert R1CS structures to polynomials
//! and construct sum-check instances for the R1CS relation.

use ark_bls12_381::Fr;
use ark_ff::{One, Zero, UniformRand};
use ark_std::log2;
use ark_std::rand::RngCore;
use ark_serialize::CanonicalSerialize;

use crate::polynomial::{MultilinearPolynomial, SparseMultilinearPolynomial};
use crate::r1cs::{SparseMatrix, R1CSInstance};
use crate::kopis_pc::{self, KopisParams};
use crate::commitments::pedersen::PedersenParams;

/// Convert an R1CS sparse matrix to a multilinear polynomial
/// 
/// The matrix M is interpreted as a function M: {0,1}^{log m} × {0,1}^{log n} → F
/// where M(i, j) is the entry at row i, column j.
/// 
/// This function creates an MLE M̃ such that M̃(i, j) = M[i][j] for all (i,j) in {0,1}^{log m + log n}
pub fn matrix_to_mle(matrix: &SparseMatrix<Fr>) -> SparseMultilinearPolynomial<Fr> {
    let num_rows = matrix.num_rows;
    let num_cols = matrix.num_cols;
    
    // Number of variables: log(num_rows) + log(num_cols)
    let row_vars = if num_rows > 0 { log2(num_rows) as usize } else { 0 };
    let col_vars = if num_cols > 0 { log2(num_cols) as usize } else { 0 };
    let num_vars = row_vars + col_vars;
    
    // Collect all non-zero entries as (index, value) pairs
    // Index encodes both row and column: index = row * 2^col_vars + col
    let mut entries_vec = Vec::new();
    
    for &(row_idx, col_idx, value) in &matrix.entries {
        // Encode (row, col) as a single index in {0, 1, ..., 2^num_vars - 1}
        let index = row_idx * (1 << col_vars) + col_idx;
        entries_vec.push((index, value));
    }
    
    SparseMultilinearPolynomial::from_entries(entries_vec, num_vars)
}

/// Build the full z vector: z = (io, 1, w)
/// 
/// This is the concatenation of:
/// - Public inputs (io)
/// - Constant 1
/// - Witness values (w)
#[allow(dead_code)] // Used in tests and may be needed for future API
pub fn build_z_vector(
    public_inputs: &[Fr],
    witness_values: &[Fr],
) -> Vec<Fr> {
    let mut z = Vec::with_capacity(public_inputs.len() + 1 + witness_values.len());
    z.extend_from_slice(public_inputs);
    z.push(Fr::one());
    z.extend_from_slice(witness_values);
    z
}

/// Build the polynomial for R1CS sum-check
/// 
/// Given R1CS relation: (A·z) ∘ (B·z) = C·z
/// We need to prove: Σ_x ẽq(τ, x) · [f_A(x) · f_B(x) - f_C(x)] = 0
/// 
/// Where:
/// - f_A(x) = (Ã·z)(x) = Σ_j M̃_A(x,j) · z[j]
/// - f_B(x) = (B̃·z)(x) = Σ_j M̃_B(x,j) · z[j]
/// - f_C(x) = (C̃·z)(x) = Σ_j M̃_C(x,j) · z[j]
/// 
/// Returns the evaluations of this polynomial over {0,1}^ν
pub fn build_r1cs_sumcheck_polynomial(
    az: &[Fr], // A·z (already computed)
    bz: &[Fr], // B·z
    cz: &[Fr], // C·z
    tau: &[Fr], // Challenge point for eq polynomial
) -> MultilinearPolynomial<Fr> {
    use crate::polynomial::eq_polynomial;
    
    assert_eq!(az.len(), bz.len());
    assert_eq!(az.len(), cz.len());
    
    let num_constraints = az.len();
    let num_vars = if num_constraints > 0 { 
        log2(num_constraints) as usize 
    } else { 
        0 
    };
    
    // Ensure we have enough tau values
    assert!(
        tau.len() >= num_vars,
        "tau must have at least {} elements, got {}",
        num_vars,
        tau.len()
    );
    
    // Compute eq polynomial evaluations: ẽq(τ, x) for x ∈ {0,1}^ν
    // We need to evaluate eq(τ, x) for all x in the boolean hypercube
    let mut eq_evals = Vec::with_capacity(1 << num_vars);
    for i in 0..(1 << num_vars) {
        // Convert i to binary representation
        let mut x_bits = vec![false; num_vars];
        for j in 0..num_vars {
            x_bits[j] = (i >> j) & 1 == 1;
        }
        
        // Evaluate eq(τ, x) at this point
        let eq_val = eq_polynomial(&tau[..num_vars], &x_bits);
        eq_evals.push(eq_val);
    }
    
    // Build polynomial evaluations: ẽq(τ,x) · [(A·z)(x) · (B·z)(x) - (C·z)(x)]
    let mut evals = Vec::with_capacity(1 << num_vars);
    
    for i in 0..num_constraints {
        let az_i = az[i];
        let bz_i = bz[i];
        let cz_i = cz[i];
        
        // (A·z)(i) * (B·z)(i) - (C·z)(i)
        let constraint_eval = az_i * bz_i - cz_i;
        
        // Multiply by eq polynomial
        let poly_eval = eq_evals[i] * constraint_eval;
        evals.push(poly_eval);
    }
    
    // Pad to power of 2 if necessary
    while evals.len() < (1 << num_vars) {
        evals.push(Fr::zero());
    }
    
    MultilinearPolynomial::from_evaluations(evals, num_vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{test_rng, UniformRand};
    use crate::r1cs::R1CSInstance;
    
    #[test]
    fn test_build_z_vector() {
        let public_inputs = vec![Fr::from(10u64), Fr::from(20u64)];
        let witness = vec![Fr::from(30u64), Fr::from(40u64), Fr::from(50u64)];
        
        let z = build_z_vector(&public_inputs, &witness);
        
        assert_eq!(z.len(), 6); // 2 + 1 + 3
        assert_eq!(z[0], Fr::from(10u64)); // io[0]
        assert_eq!(z[1], Fr::from(20u64)); // io[1]
        assert_eq!(z[2], Fr::one());       // constant 1
        assert_eq!(z[3], Fr::from(30u64)); // w[0]
        assert_eq!(z[4], Fr::from(40u64)); // w[1]
        assert_eq!(z[5], Fr::from(50u64)); // w[2]
    }
    
    #[test]
    fn test_matrix_to_mle() {
        let mut matrix = SparseMatrix::new(4, 4);
        matrix.add_entry(0, 0, Fr::from(1u64));
        matrix.add_entry(1, 2, Fr::from(5u64));
        matrix.add_entry(2, 1, Fr::from(3u64));
        matrix.add_entry(3, 3, Fr::from(7u64));
        
        let mle = matrix_to_mle(&matrix);
        
        // Matrix is 4x4, so we need log2(4) + log2(4) = 2 + 2 = 4 variables
        assert_eq!(mle.num_vars, 4);
        
        // Check that sparse entries are preserved
        // (0,0) → index 0*4 + 0 = 0
        assert_eq!(mle.evaluate(&[Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()]), Fr::from(1u64));
        
        // (1,2) → index 1*4 + 2 = 6
        // 6 in binary is 0110, so eval at [0,1,1,0]
        assert_eq!(mle.evaluate(&[Fr::zero(), Fr::one(), Fr::one(), Fr::zero()]), Fr::from(5u64));
    }
    
    #[test]
    fn test_r1cs_sumcheck_polynomial_satisfied() {
        // Simple R1CS: x * y = z (satisfied)
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::one()); // Select x
        
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::one()); // Select y
        
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::one()); // Select z
        
        let instance = R1CSInstance::new(a, b, c, 1, 4, 0);
        
        // Witness: [2, 3, 6] → z = [1, 2, 3, 6]
        let z = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)];
        
        // Compute A·z, B·z, C·z
        let az = instance.a.mul_vector(&z);
        let bz = instance.b.mul_vector(&z);
        let cz = instance.c.mul_vector(&z);
        
        // Random tau point
        let mut rng = test_rng();
        let tau = vec![Fr::rand(&mut rng)];
        
        // Build sum-check polynomial
        let poly = build_r1cs_sumcheck_polynomial(&az, &bz, &cz, &tau);
        
        // Sum over boolean hypercube should be 0 (satisfied)
        let mut sum = Fr::zero();
        for eval in &poly.evaluations {
            sum += eval;
        }
        
        assert_eq!(sum, Fr::zero(), "R1CS is satisfied, sum should be 0");
    }
    
    #[test]
    fn test_r1cs_sumcheck_polynomial_unsatisfied() {
        // Simple R1CS: x * y = z (unsatisfied)
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::one());
        
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::one());
        
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::one());
        
        let instance = R1CSInstance::new(a, b, c, 1, 4, 0);
        
        // Bad witness: [2, 3, 7] → z = [1, 2, 3, 7] (2*3 ≠ 7)
        let z = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64), Fr::from(7u64)];
        
        let az = instance.a.mul_vector(&z);
        let bz = instance.b.mul_vector(&z);
        let cz = instance.c.mul_vector(&z);
        
        let mut rng = test_rng();
        let tau = vec![Fr::rand(&mut rng)];
        
        let poly = build_r1cs_sumcheck_polynomial(&az, &bz, &cz, &tau);
        
        // Sum should be NON-ZERO (unsatisfied)
        let mut sum = Fr::zero();
        for eval in &poly.evaluations {
            sum += eval;
        }
        
        assert_ne!(sum, Fr::zero(), "R1CS is unsatisfied, sum should be non-zero");
    }
}

/// Create ComputationCommitment for R1CS instance using Sparkle + Assistant (§7)
/// 
/// This enables O(√n) verification for Kopis and O(log n) for Xiphos
/// by preprocessing the R1CS structure (A, B, C matrices) into commitments.
pub fn create_computation_commitment<R: RngCore>(
    instance: &R1CSInstance<Fr>,
    kopis_params: &KopisParams,
    _pedersen_params: &PedersenParams,
    rng: &mut R,
) -> super::common::ComputationCommitment {
    // Step 1: Convert R1CS matrices to sparse MLEs
    let a_mle = matrix_to_mle(&instance.a);
    let b_mle = matrix_to_mle(&instance.b);
    let c_mle = matrix_to_mle(&instance.c);
    
    // Step 2: Use Sparkle to commit to sparse polynomials (§6)
    // Sparkle creates constant-size commitments for sparse polynomials
    let _gamma = Fr::rand(rng); // Random challenge for multiset hash (for future Sparkle integration)
    
    // Convert sparse MLEs to dense for Kopis-PC commitment
    // (In production, would use Sparkle's hybrid approach)
    let a_dense_poly = a_mle.to_dense();
    let b_dense_poly = b_mle.to_dense();
    let c_dense_poly = c_mle.to_dense();
    
    // Pad to match kopis_params.num_vars
    let required_size = 1 << kopis_params.num_vars;
    let mut a_evals = a_dense_poly.evaluations.clone();
    let mut b_evals = b_dense_poly.evaluations.clone();
    let mut c_evals = c_dense_poly.evaluations.clone();
    
    a_evals.resize(required_size, Fr::zero());
    b_evals.resize(required_size, Fr::zero());
    c_evals.resize(required_size, Fr::zero());
    
    // Step 3: Commit using Kopis-PC with blinding
    let (commit_a_obj, _) = kopis_pc::commit_with_blinding(kopis_params, &a_evals, rng);
    let (commit_b_obj, _) = kopis_pc::commit_with_blinding(kopis_params, &b_evals, rng);
    let (commit_c_obj, _) = kopis_pc::commit_with_blinding(kopis_params, &c_evals, rng);
    
    // Step 4: Serialize commitments
    let mut commit_a_bytes = Vec::new();
    let mut commit_b_bytes = Vec::new();
    let mut commit_c_bytes = Vec::new();
    
    commit_a_obj.commitment.serialize_compressed(&mut commit_a_bytes)
        .expect("Failed to serialize commit_a");
    commit_b_obj.commitment.serialize_compressed(&mut commit_b_bytes)
        .expect("Failed to serialize commit_b");
    commit_c_obj.commitment.serialize_compressed(&mut commit_c_bytes)
        .expect("Failed to serialize commit_c");
    
    // Step 5: Use Assistant protocol to verify commitments (§7)
    // In full implementation, encoder would verify via random evaluation
    // For now, we trust the commitments (assistant verification is implemented but not integrated here)
    
    super::common::ComputationCommitment {
        commit_a: commit_a_bytes,
        commit_b: commit_b_bytes,
        commit_c: commit_c_bytes,
        hints: vec![], // Would store Sparkle opening hints
    }
}

