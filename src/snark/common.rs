//! Common structures for Quarks zkSNARKs
//!
//! Provides generic SNARK parameters that can work with any PCS implementing
//! the `PolynomialCommitmentScheme` trait.

use ark_bls12_381::Fr;
use ark_std::vec::Vec;
use ark_std::rand::RngCore;
use core::marker::PhantomData;

use crate::traits::PolynomialCommitmentScheme;
use crate::commitments::pedersen::PedersenParams;

/// Generic public parameters for a Quarks SNARK
/// 
/// This struct is parameterized over the PCS (Polynomial Commitment Scheme),
/// allowing SNARKs to use different PCS backends without code changes.
/// 
/// # Type Parameters
/// - `PCS`: The polynomial commitment scheme (e.g., `KopisPCS`, `DoryPCS`)
/// 
/// # Example
/// ```ignore
/// // Use with Kopis-PC (O(√n) verification)
/// let params: GenericSnarkParams<KopisPCS> = GenericSnarkParams::setup(16, &mut rng);
/// 
/// // Use with Dory-PC (O(log n) verification)
/// let params: GenericSnarkParams<DoryPCS> = GenericSnarkParams::setup(16, &mut rng);
/// ```
#[derive(Clone, Debug)]
pub struct GenericSnarkParams<PCS: PolynomialCommitmentScheme<Fr>> {
    /// Parameters for polynomial commitments (generic over PCS)
    pub pcs_params: PCS::Params,
    /// Parameters for Pedersen commitments (for field elements)
    pub pedersen_params: PedersenParams,
    /// Maximum number of variables supported
    pub max_num_vars: usize,
    /// Marker for PCS type
    _marker: PhantomData<PCS>,
}

impl<PCS: PolynomialCommitmentScheme<Fr>> GenericSnarkParams<PCS> {
    /// Setup public parameters for the SNARK with given PCS
    pub fn setup<R: RngCore>(max_num_vars: usize, rng: &mut R) -> Self {
        let pcs_params = PCS::setup(max_num_vars, rng);
        let pedersen_params = PedersenParams::new();
        
        Self {
            pcs_params,
            pedersen_params,
            max_num_vars,
            _marker: PhantomData,
        }
    }
    
    /// Get a reference to the PCS parameters
    pub fn pcs_params(&self) -> &PCS::Params {
        &self.pcs_params
    }
}

/// A zkSNARK proof for R1CS
/// 
/// Contains all proof components that prover sends to verifier
#[derive(Clone, Debug)]
pub struct Proof {
    /// Digest of the R1CS instance (for binding proof to specific circuit)
    /// 
    /// SECURITY: This field prevents proof malleability - same proof cannot
    /// verify for different instances. Added in v0.1.3.
    pub instance_digest: [u8; 32],
    /// Commitment to witness polynomial (serialized)
    pub witness_commitment: Vec<u8>,
    /// Sum-check proofs (may be multiple rounds)
    pub sumcheck_proofs: Vec<Vec<Fr>>,
    /// Polynomial evaluation claims (batched values)
    pub eval_proofs: Vec<Vec<u8>>,
    /// PCS evaluation proof (serialized PCS::EvaluationProof)
    pub pcs_eval_proof: Vec<u8>,
    /// Evaluation point for PCS verification
    pub eval_point: Vec<Fr>,
    /// Claimed evaluation value at eval_point
    pub claimed_eval: Fr,
    /// Additional metadata
    pub metadata: ProofMetadata,
}

/// Metadata about a proof
#[derive(Clone, Debug)]
pub struct ProofMetadata {
    /// Number of constraints in R1CS instance
    pub num_constraints: usize,
    /// Number of variables
    pub num_variables: usize,
    /// Proof generation timestamp (for benchmarking)
    pub timestamp: u64,
}

/// Computation commitment (verifier's preprocessing output)
/// 
/// Contains commitments to structure matrices Ã, B̃, C̃ of R1CS instance
#[derive(Clone, Debug)]
pub struct ComputationCommitment {
    /// Commitment to matrix A
    pub commit_a: Vec<u8>,
    /// Commitment to matrix B
    pub commit_b: Vec<u8>,
    /// Commitment to matrix C
    pub commit_c: Vec<u8>,
    /// Opening hints (if needed)
    pub hints: Vec<Vec<u8>>,
}

impl ComputationCommitment {
    /// Create a placeholder computation commitment
    pub fn placeholder() -> Self {
        Self {
            commit_a: vec![0u8; 32],
            commit_b: vec![0u8; 32],
            commit_c: vec![0u8; 32],
            hints: vec![],
        }
    }
}

/// Witness for R1CS instance
#[derive(Clone, Debug)]
pub struct Witness {
    /// Witness values w ∈ F^{m - |io| - 1}
    pub values: Vec<Fr>,
}

impl Witness {
    pub fn new(values: Vec<Fr>) -> Self {
        Self { values }
    }
    
    pub fn len(&self) -> usize {
        self.values.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use crate::kopis_pc::KopisPCS;
    use crate::dory_pc::DoryPCS;

    #[test]
    fn generic_snark_params_kopis() {
        let mut rng = test_rng();
        let params: GenericSnarkParams<KopisPCS> = GenericSnarkParams::setup(4, &mut rng);
        assert_eq!(params.max_num_vars, 4);
        assert_eq!(params.pcs_params.num_vars, 4);
    }
    
    #[test]
    fn generic_snark_params_dory() {
        let mut rng = test_rng();
        let params: GenericSnarkParams<DoryPCS> = GenericSnarkParams::setup(4, &mut rng);
        assert_eq!(params.max_num_vars, 4);
    }

    #[test]
    fn computation_commitment_placeholder() {
        let cc = ComputationCommitment::placeholder();
        assert_eq!(cc.commit_a.len(), 32);
        assert_eq!(cc.commit_b.len(), 32);
        assert_eq!(cc.commit_c.len(), 32);
    }

    #[test]
    fn witness_basic() {
        let w = Witness::new(vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(w.len(), 3);
        assert!(!w.is_empty());
    }
}

