//! Polynomial Commitment Scheme (PCS) trait abstraction
//!
//! A PCS allows a prover to commit to a polynomial and later prove
//! evaluations at specific points without revealing the polynomial.
//!
//! # Supported Schemes
//!
//! This trait is implemented by:
//! - `KopisPCS` - Constant-size commitment, O(√n) verification
//! - `DoryPCS` - Constant-size commitment, O(log n) verification
//!
//! # Usage
//!
//! ```ignore
//! use quarks::traits::PolynomialCommitmentScheme;
//!
//! // Use any PCS with a SNARK
//! let snark = XiphosSnark::<DoryPCS>::setup(16);
//! let snark_alt = XiphosSnark::<KopisPCS>::setup(16);  // Swap trivially!
//! ```

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core::fmt::Debug;

/// Core trait for Polynomial Commitment Schemes
///
/// Implementors must provide:
/// - Setup: Generate public parameters
/// - Commit: Create a binding commitment to a polynomial
/// - Prove: Generate an evaluation proof at a point
/// - Verify: Check that an evaluation proof is valid
///
/// # Type Parameters
///
/// - `F`: The scalar field for polynomial coefficients
pub trait PolynomialCommitmentScheme<F: Field>: Clone + Send + Sync + Debug {
    /// Public parameters for the scheme (prover + verifier)
    type Params: Clone + Send + Sync + Debug;
    
    /// Commitment to a polynomial (typically a group element or hash)
    type Commitment: Clone 
        + Send 
        + Sync 
        + Debug 
        + PartialEq 
        + Eq
        + CanonicalSerialize 
        + CanonicalDeserialize;
    
    /// Proof that a polynomial evaluates to a specific value at a point
    type EvaluationProof: Clone 
        + Send 
        + Sync 
        + Debug
        + CanonicalSerialize 
        + CanonicalDeserialize;
    
    /// Generate public parameters for polynomials up to `max_vars` variables
    ///
    /// # Arguments
    /// - `max_vars`: Maximum number of variables (log₂ of polynomial size)
    /// - `rng`: Random number generator for any randomness needed
    ///
    /// # Returns
    /// Public parameters that can be used for commit/prove/verify
    fn setup<R: RngCore>(max_vars: usize, rng: &mut R) -> Self::Params;
    
    /// Commit to a multilinear polynomial given its evaluations
    ///
    /// # Arguments
    /// - `params`: Public parameters from setup
    /// - `evaluations`: Evaluations of the polynomial over the boolean hypercube
    ///                  (length must be 2^num_vars)
    ///
    /// # Returns
    /// A binding commitment to the polynomial
    fn commit(params: &Self::Params, evaluations: &[F]) -> Self::Commitment;
    
    /// Commit with explicit blinding factor (for zero-knowledge)
    ///
    /// # Arguments
    /// - `params`: Public parameters from setup
    /// - `evaluations`: Evaluations of the polynomial
    /// - `rng`: RNG for generating blinding factors
    ///
    /// # Returns
    /// A hiding commitment to the polynomial
    fn commit_hiding<R: RngCore>(
        params: &Self::Params, 
        evaluations: &[F],
        rng: &mut R,
    ) -> Self::Commitment;
    
    /// Prove that a committed polynomial evaluates to `value` at `point`
    ///
    /// # Arguments
    /// - `params`: Public parameters
    /// - `evaluations`: The polynomial's evaluations (prover knows this)
    /// - `point`: The evaluation point (vector of field elements)
    /// - `rng`: RNG for any proof randomness
    ///
    /// # Returns
    /// - The evaluation value f(point)
    /// - A proof that the committed polynomial evaluates to this value
    fn prove_eval<R: RngCore>(
        params: &Self::Params,
        evaluations: &[F],
        point: &[F],
        rng: &mut R,
    ) -> (F, Self::EvaluationProof);
    
    /// Verify an evaluation proof
    ///
    /// # Arguments
    /// - `params`: Public parameters
    /// - `commitment`: The polynomial commitment
    /// - `point`: The evaluation point
    /// - `value`: The claimed evaluation value
    /// - `proof`: The evaluation proof
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    fn verify_eval(
        params: &Self::Params,
        commitment: &Self::Commitment,
        point: &[F],
        value: F,
        proof: &Self::EvaluationProof,
    ) -> bool;
    
    /// Get the size of a commitment in bytes (for proof size analysis)
    fn commitment_size(commitment: &Self::Commitment) -> usize {
        let mut buf = Vec::new();
        if commitment.serialize_compressed(&mut buf).is_ok() {
            buf.len()
        } else {
            0
        }
    }
    
    /// Get the size of an evaluation proof in bytes
    fn proof_size(proof: &Self::EvaluationProof) -> usize {
        let mut buf = Vec::new();
        if proof.serialize_compressed(&mut buf).is_ok() {
            buf.len()
        } else {
            0
        }
    }
}

/// Marker trait for PCS schemes that support batching
///
/// Batching allows combining multiple evaluation proofs into one,
/// reducing proof size by 26-36%.
pub trait BatchablePCS<F: Field>: PolynomialCommitmentScheme<F> {
    /// Batch evaluation proof type (may be different from single proof)
    type BatchProof: Clone + Send + Sync + Debug + CanonicalSerialize + CanonicalDeserialize;
    
    /// Prove multiple evaluations in a single proof
    fn prove_batch<R: RngCore>(
        params: &Self::Params,
        polynomials: &[&[F]],  // Multiple polynomials
        points: &[&[F]],       // Evaluation points (one per poly)
        rng: &mut R,
    ) -> (Vec<F>, Self::BatchProof);  // Values + single batch proof
    
    /// Verify a batch evaluation proof
    fn verify_batch(
        params: &Self::Params,
        commitments: &[Self::Commitment],
        points: &[&[F]],
        values: &[F],
        proof: &Self::BatchProof,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    
    /// Mock PCS for testing trait compilation
    #[derive(Clone, Debug)]
    struct MockPCS;
    
    #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
    struct MockCommitment(u64);
    
    #[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
    struct MockProof(Vec<u8>);
    
    #[derive(Clone, Debug)]
    struct MockParams {
        max_vars: usize,
    }
    
    impl PolynomialCommitmentScheme<Fr> for MockPCS {
        type Params = MockParams;
        type Commitment = MockCommitment;
        type EvaluationProof = MockProof;
        
        fn setup<R: RngCore>(max_vars: usize, _rng: &mut R) -> Self::Params {
            MockParams { max_vars }
        }
        
        fn commit(_params: &Self::Params, evaluations: &[Fr]) -> Self::Commitment {
            // Trivial mock: sum of evaluations (NOT cryptographically secure!)
            let sum: u64 = evaluations.len() as u64;
            MockCommitment(sum)
        }
        
        fn commit_hiding<R: RngCore>(
            params: &Self::Params, 
            evaluations: &[Fr],
            _rng: &mut R,
        ) -> Self::Commitment {
            Self::commit(params, evaluations)
        }
        
        fn prove_eval<R: RngCore>(
            _params: &Self::Params,
            evaluations: &[Fr],
            point: &[Fr],
            _rng: &mut R,
        ) -> (Fr, Self::EvaluationProof) {
            // Mock: just return first evaluation and empty proof
            let value = if evaluations.is_empty() { Fr::from(0u64) } else { evaluations[0] };
            let proof_data = point.len().to_le_bytes().to_vec();
            (value, MockProof(proof_data))
        }
        
        fn verify_eval(
            _params: &Self::Params,
            _commitment: &Self::Commitment,
            _point: &[Fr],
            _value: Fr,
            _proof: &Self::EvaluationProof,
        ) -> bool {
            // Mock: always accept (NOT secure!)
            true
        }
    }
    
    #[test]
    fn test_pcs_trait_compiles() {
        // This test verifies the trait definition is valid and can be implemented
        let mut rng = test_rng();
        let params = MockPCS::setup(10, &mut rng);
        assert_eq!(params.max_vars, 10);
    }
    
    #[test]
    fn test_pcs_mock_workflow() {
        let mut rng = test_rng();
        let params = MockPCS::setup(4, &mut rng);
        
        // Create polynomial evaluations (2^4 = 16 elements)
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        
        // Commit
        let commitment = MockPCS::commit(&params, &evals);
        assert_eq!(commitment.0, 16);
        
        // Prove
        let point: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let (value, proof) = MockPCS::prove_eval(&params, &evals, &point, &mut rng);
        
        // Verify
        let valid = MockPCS::verify_eval(&params, &commitment, &point, value, &proof);
        assert!(valid);
    }
    
    #[test]
    fn test_pcs_commitment_size() {
        let mut rng = test_rng();
        let params = MockPCS::setup(4, &mut rng);
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let commitment = MockPCS::commit(&params, &evals);
        
        let size = MockPCS::commitment_size(&commitment);
        assert!(size > 0, "Commitment should have non-zero size");
    }
    
    #[test]
    fn test_pcs_proof_size() {
        let mut rng = test_rng();
        let params = MockPCS::setup(4, &mut rng);
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let point: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let (_, proof) = MockPCS::prove_eval(&params, &evals, &point, &mut rng);
        
        let size = MockPCS::proof_size(&proof);
        assert!(size > 0, "Proof should have non-zero size");
    }
    
    /// Test that generic functions work with trait bounds
    fn generic_commit_test<PCS: PolynomialCommitmentScheme<Fr>>(
        params: &PCS::Params,
        evals: &[Fr],
    ) -> PCS::Commitment {
        PCS::commit(params, evals)
    }
    
    #[test]
    fn test_generic_function_with_mock() {
        let mut rng = test_rng();
        let params = MockPCS::setup(4, &mut rng);
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        
        // This proves we can use generic functions with trait bounds
        let commitment = generic_commit_test::<MockPCS>(&params, &evals);
        assert_eq!(commitment.0, 16);
    }
}

