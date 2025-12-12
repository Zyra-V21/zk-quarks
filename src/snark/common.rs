//! Common structures for Quarks zkSNARKs
//!
//! Provides generic SNARK parameters that can work with any PCS implementing
//! the `PolynomialCommitmentScheme` trait.

use ark_bls12_381::Fr;
use ark_ff::One;
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
/// 
/// z vector structure: [public_inputs..., 1, assignments...]
#[derive(Clone, Debug)]
pub struct Witness {
    /// Public inputs (io) - visible to verifier
    pub public_inputs: Vec<Fr>,
    /// Private assignments (w) - hidden from verifier
    pub assignments: Vec<Fr>,
}

impl Witness {
    /// Create witness with both public inputs and private assignments
    pub fn new(public_inputs: Vec<Fr>, assignments: Vec<Fr>) -> Self {
        Self { public_inputs, assignments }
    }
    
    /// Create witness with only private values (for backwards compatibility)
    /// Assumes no public inputs
    pub fn from_assignments(assignments: Vec<Fr>) -> Self {
        Self { 
            public_inputs: vec![], 
            assignments 
        }
    }
    
    /// Total number of witness values (excluding constant 1)
    pub fn len(&self) -> usize {
        self.public_inputs.len() + self.assignments.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.public_inputs.is_empty() && self.assignments.is_empty()
    }
    
    /// Build z vector = [public_inputs, 1, assignments]
    pub fn build_z(&self) -> Vec<Fr> {
        let mut z = Vec::with_capacity(self.public_inputs.len() + 1 + self.assignments.len());
        z.extend_from_slice(&self.public_inputs);
        z.push(Fr::one());
        z.extend_from_slice(&self.assignments);
        z
    }
    
    /// Number of public inputs
    pub fn num_inputs(&self) -> usize {
        self.public_inputs.len()
    }
    
    /// Number of private assignments
    pub fn num_witness(&self) -> usize {
        self.assignments.len()
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
        let w = Witness::from_assignments(vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(w.len(), 3);
        assert!(!w.is_empty());
    }
}

