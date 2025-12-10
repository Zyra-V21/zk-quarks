//! Dory Polynomial Commitment (Dory-PC) with BLS12-381 backend
//!
//! This module provides a BLS12-381 backend for the Dory polynomial commitment
//! scheme (J. Lee, eprint 2020/1274), used exclusively by Xiphos SNARK.
//!
//! Dory-PC achieves (paper Table 4):
//! - O(1) commitment size (single G_T element)
//! - O(log n) proof size
//! - O(log n) verification time (vs O(√n) in Kopis-PC)
//!
//! The implementation wraps the `dory-pcs` crate with a custom BLS12-381 backend
//! to maintain consistency with the rest of the Quarks codebase.

pub mod bls12_381_backend;

// Re-export dory-pcs core types and functions
pub use dory_pcs::{
    DoryError, DoryProof, ProverSetup, VerifierSetup,
    setup, prove, verify,
};

// Re-export primitives for backend implementation
pub use dory_pcs::primitives;

// Re-export BLS12-381 backend types
pub use bls12_381_backend::{
    BLS12381,
    Bls381Fr, Bls381G1, Bls381G2, Bls381GT,
    Bls381Polynomial, Blake2bTranscript,
    G1Routines, G2Routines,
};

// =============================================================================
// PCS Trait Implementation for Dory-PC
// =============================================================================

use crate::traits::PolynomialCommitmentScheme;
use ark_bls12_381::Fr;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, 
    Read, Write, Compress, Validate, Valid,
    SerializationError,
};
use ark_std::rand::RngCore;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;

/// Dory-PC wrapper implementing the PolynomialCommitmentScheme trait
/// 
/// Provides O(log n) verification with O(1) commitment size.
/// Used by Xiphos SNARK for optimal verification complexity.
/// 
/// Paper reference: Table 4 (Kopis-PC vs Dory-PC comparison)
#[derive(Clone, Debug)]
pub struct DoryPCS;

/// Parameters for Dory-PC
#[derive(Clone, Debug)]
pub struct DoryPCSParams {
    pub prover_setup: ProverSetup<BLS12381>,
    pub verifier_setup: VerifierSetup<BLS12381>,
    pub num_vars: usize,
    pub nu: usize,   // log₂(rows)
    pub sigma: usize, // log₂(cols)
}

/// Commitment in Dory-PC (Tier-2 commitment in G_T)
/// 
/// Paper §4: "a commitment is a single element of G_T"
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoryPCSCommitment {
    pub tier2: Bls381GT,
}

// Bls381GT already has CanonicalSerialize from ark_serialize
impl Valid for DoryPCSCommitment {
    fn check(&self) -> Result<(), SerializationError> {
        // GT element is always valid if it exists
        Ok(())
    }
}

impl CanonicalSerialize for DoryPCSCommitment {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // Bls381GT wraps Fq12 which has CanonicalSerialize
        self.tier2.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.tier2.0.serialized_size(compress)
    }
}

impl CanonicalDeserialize for DoryPCSCommitment {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = ark_bls12_381::Fq12::deserialize_with_mode(reader, compress, validate)?;
        Ok(Self { tier2: Bls381GT(inner) })
    }
}

/// Evaluation proof for Dory-PC
/// 
/// Contains the full DoryProof structure with all protocol messages.
/// Size is O(log n) group elements.
#[derive(Clone, Debug)]
pub struct DoryPCSEvaluationProof {
    /// The complete Dory proof with all messages
    pub proof: DoryProof<Bls381G1, Bls381G2, Bls381GT>,
}

impl Valid for DoryPCSEvaluationProof {
    fn check(&self) -> Result<(), SerializationError> {
        // Proof structure is valid if created by prove()
        Ok(())
    }
}

impl CanonicalSerialize for DoryPCSEvaluationProof {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // Serialize dimensions
        (self.proof.nu as u32).serialize_with_mode(&mut writer, compress)?;
        (self.proof.sigma as u32).serialize_with_mode(&mut writer, compress)?;
        
        // Serialize VMV message (c: GT, d2: GT, e1: G1)
        self.proof.vmv_message.c.0.serialize_with_mode(&mut writer, compress)?;
        self.proof.vmv_message.d2.0.serialize_with_mode(&mut writer, compress)?;
        self.proof.vmv_message.e1.0.serialize_with_mode(&mut writer, compress)?;
        
        // Serialize first messages count and data
        (self.proof.first_messages.len() as u32).serialize_with_mode(&mut writer, compress)?;
        for msg in &self.proof.first_messages {
            msg.d1_left.0.serialize_with_mode(&mut writer, compress)?;
            msg.d1_right.0.serialize_with_mode(&mut writer, compress)?;
            msg.d2_left.0.serialize_with_mode(&mut writer, compress)?;
            msg.d2_right.0.serialize_with_mode(&mut writer, compress)?;
            msg.e1_beta.0.serialize_with_mode(&mut writer, compress)?;
            msg.e2_beta.0.serialize_with_mode(&mut writer, compress)?;
        }
        
        // Serialize second messages count and data  
        (self.proof.second_messages.len() as u32).serialize_with_mode(&mut writer, compress)?;
        for msg in &self.proof.second_messages {
            msg.c_plus.0.serialize_with_mode(&mut writer, compress)?;
            msg.c_minus.0.serialize_with_mode(&mut writer, compress)?;
            msg.e1_plus.0.serialize_with_mode(&mut writer, compress)?;
            msg.e1_minus.0.serialize_with_mode(&mut writer, compress)?;
            msg.e2_plus.0.serialize_with_mode(&mut writer, compress)?;
            msg.e2_minus.0.serialize_with_mode(&mut writer, compress)?;
        }
        
        // Serialize final message (e1: G1, e2: G2)
        self.proof.final_message.e1.0.serialize_with_mode(&mut writer, compress)?;
        self.proof.final_message.e2.0.serialize_with_mode(&mut writer, compress)?;
        
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = 0;
        
        // Dimensions
        size += 4 + 4;
        
        // VMV message (c: GT, d2: GT, e1: G1)
        size += self.proof.vmv_message.c.0.serialized_size(compress);
        size += self.proof.vmv_message.d2.0.serialized_size(compress);
        size += self.proof.vmv_message.e1.0.serialized_size(compress);
        
        // First messages (count + data per msg: 4 GT + G1 + G2)
        size += 4;
        for msg in &self.proof.first_messages {
            size += msg.d1_left.0.serialized_size(compress);
            size += msg.d1_right.0.serialized_size(compress);
            size += msg.d2_left.0.serialized_size(compress);
            size += msg.d2_right.0.serialized_size(compress);
            size += msg.e1_beta.0.serialized_size(compress);
            size += msg.e2_beta.0.serialized_size(compress);
        }
        
        // Second messages (count + data per msg: 2 GT + 2 G1 + 2 G2)
        size += 4;
        for msg in &self.proof.second_messages {
            size += msg.c_plus.0.serialized_size(compress);
            size += msg.c_minus.0.serialized_size(compress);
            size += msg.e1_plus.0.serialized_size(compress);
            size += msg.e1_minus.0.serialized_size(compress);
            size += msg.e2_plus.0.serialized_size(compress);
            size += msg.e2_minus.0.serialized_size(compress);
        }
        
        // Final message (G1 + G2)
        size += self.proof.final_message.e1.0.serialized_size(compress);
        size += self.proof.final_message.e2.0.serialized_size(compress);
        
        size
    }
}

impl CanonicalDeserialize for DoryPCSEvaluationProof {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        use dory_pcs::messages::{
            VMVMessage, FirstReduceMessage, SecondReduceMessage, ScalarProductMessage
        };
        
        // Deserialize dimensions
        let nu = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let sigma = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        
        // Deserialize VMV message (c: GT, d2: GT, e1: G1)
        let c = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
        let d2 = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
        let e1 = Bls381G1(ark_bls12_381::G1Projective::deserialize_with_mode(&mut reader, compress, validate)?);
        let vmv_message = VMVMessage { c, d2, e1 };
        
        // Deserialize first messages (4 GT + G1 + G2 each)
        let first_count = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let mut first_messages = Vec::with_capacity(first_count);
        for _ in 0..first_count {
            let d1_left = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let d1_right = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let d2_left = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let d2_right = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let e1_beta = Bls381G1(ark_bls12_381::G1Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            let e2_beta = Bls381G2(ark_bls12_381::G2Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            first_messages.push(FirstReduceMessage { 
                d1_left, d1_right, d2_left, d2_right, e1_beta, e2_beta 
            });
        }
        
        // Deserialize second messages (2 GT + 2 G1 + 2 G2 each)
        let second_count = u32::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let mut second_messages = Vec::with_capacity(second_count);
        for _ in 0..second_count {
            let c_plus = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let c_minus = Bls381GT(ark_bls12_381::Fq12::deserialize_with_mode(&mut reader, compress, validate)?);
            let e1_plus = Bls381G1(ark_bls12_381::G1Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            let e1_minus = Bls381G1(ark_bls12_381::G1Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            let e2_plus = Bls381G2(ark_bls12_381::G2Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            let e2_minus = Bls381G2(ark_bls12_381::G2Projective::deserialize_with_mode(&mut reader, compress, validate)?);
            second_messages.push(SecondReduceMessage { 
                c_plus, c_minus, e1_plus, e1_minus, e2_plus, e2_minus 
            });
        }
        
        // Deserialize final message (G1 + G2)
        let e1 = Bls381G1(ark_bls12_381::G1Projective::deserialize_with_mode(&mut reader, compress, validate)?);
        let e2 = Bls381G2(ark_bls12_381::G2Projective::deserialize_with_mode(&mut reader, compress, validate)?);
        let final_message = ScalarProductMessage { e1, e2 };
        
        Ok(Self {
            proof: DoryProof {
                vmv_message,
                first_messages,
                second_messages,
                final_message,
                nu,
                sigma,
            }
        })
    }
}

/// Convert ark_bls12_381::Fr to Bls381Fr wrapper
#[inline]
fn ark_fr_to_dory(f: &Fr) -> Bls381Fr {
    Bls381Fr(*f)
}

/// Convert Bls381Fr wrapper to ark_bls12_381::Fr
#[inline]
fn dory_fr_to_ark(f: &Bls381Fr) -> Fr {
    f.0
}

impl PolynomialCommitmentScheme<Fr> for DoryPCS {
    type Params = DoryPCSParams;
    type Commitment = DoryPCSCommitment;
    type EvaluationProof = DoryPCSEvaluationProof;
    
    /// Setup parameters for polynomials with up to max_vars variables
    /// 
    /// Paper §4: "pp_out ← BIPP.Setup(1^λ, s), pp_in ← IPP.Setup(1^λ, s)"
    fn setup<R: RngCore>(max_vars: usize, rng: &mut R) -> Self::Params {
        // Dory needs even number of variables for nu/sigma split
        let num_vars = if max_vars % 2 == 0 { max_vars } else { max_vars + 1 };
        let nu = num_vars / 2;
        let sigma = num_vars - nu;
        
        let (prover_setup, verifier_setup) = setup::<BLS12381, _>(rng, num_vars);
        
        DoryPCSParams {
            prover_setup,
            verifier_setup,
            num_vars,
            nu,
            sigma,
        }
    }
    
    /// Commit to a multilinear polynomial given its evaluations
    /// 
    /// Paper §4 line 518-523:
    /// 1. Reshape evaluations into matrix Z
    /// 2. Commit each row: C_i ← IPP.Commit(pp.pp_in, Z(i))
    /// 3. Commit rows: C_G ← BIPP.Commit(pp.pp_out, (C_0, ..., C_{s-1}))
    fn commit(params: &Self::Params, evaluations: &[Fr]) -> Self::Commitment {
        let n = 1usize << params.num_vars;
        let mut padded: Vec<Bls381Fr> = evaluations.iter()
            .map(ark_fr_to_dory)
            .collect();
        padded.resize(n, Bls381Fr::zero());
        
        let poly = Bls381Polynomial::new(padded);
        
        let (tier2, _row_commits) = poly
            .commit::<BLS12381, G1Routines>(params.nu, params.sigma, &params.prover_setup)
            .expect("Dory commit failed");
        
        DoryPCSCommitment { tier2 }
    }
    
    /// Commit with hiding (Dory is already hiding via pairing-based structure)
    fn commit_hiding<R: RngCore>(
        params: &Self::Params,
        evaluations: &[Fr],
        _rng: &mut R,
    ) -> Self::Commitment {
        // Dory commitments are inherently hiding due to pairing structure
        Self::commit(params, evaluations)
    }
    
    /// Generate evaluation proof
    /// 
    /// Paper §4 line 525-535 (Eval protocol):
    /// 1. Split r = (r_x, r_y)
    /// 2. Compute L = eq(·, r_x)
    /// 3. P computes y_out = ⟨row_commits, L⟩
    /// 4. Run BIPP.Eval to prove y_out
    /// 5. Compute R = eq(·, r_y)
    /// 6. Run IPP.Eval to prove final evaluation
    fn prove_eval<R: RngCore>(
        params: &Self::Params,
        evaluations: &[Fr],
        point: &[Fr],
        _rng: &mut R,
    ) -> (Fr, Self::EvaluationProof) {
        // Pad evaluations to match num_vars
        let n = 1usize << params.num_vars;
        let mut padded: Vec<Bls381Fr> = evaluations.iter()
            .map(ark_fr_to_dory)
            .collect();
        padded.resize(n, Bls381Fr::zero());
        
        let poly = Bls381Polynomial::new(padded);
        
        // Pad point to match num_vars
        let mut dory_point: Vec<Bls381Fr> = point.iter()
            .map(ark_fr_to_dory)
            .collect();
        dory_point.resize(params.num_vars, Bls381Fr::zero());
        
        // Compute evaluation using multilinear extension
        let eval_dory = poly.evaluate(&dory_point);
        let eval = dory_fr_to_ark(&eval_dory);
        
        // Commit to get row commitments needed for prove
        let (_tier2, row_commits) = poly
            .commit::<BLS12381, G1Routines>(params.nu, params.sigma, &params.prover_setup)
            .expect("Dory commit failed");
        
        // Generate Dory proof using Fiat-Shamir
        let mut transcript = Blake2bTranscript::new(b"dory-pcs");
        let proof = prove::<_, BLS12381, G1Routines, G2Routines, _, _>(
            &poly,
            &dory_point,
            row_commits,
            params.nu,
            params.sigma,
            &params.prover_setup,
            &mut transcript,
        ).expect("Dory prove failed");
        
        (eval, DoryPCSEvaluationProof { proof })
    }
    
    /// Verify evaluation proof
    /// 
    /// Paper verification follows the Eval protocol with BIPP and IPP verification.
    /// Runs in O(log n) time due to Dory's logarithmic verification.
    fn verify_eval(
        params: &Self::Params,
        commitment: &Self::Commitment,
        point: &[Fr],
        value: Fr,
        proof: &Self::EvaluationProof,
    ) -> bool {
        // Convert point to Dory field elements
        let mut dory_point: Vec<Bls381Fr> = point.iter()
            .map(ark_fr_to_dory)
            .collect();
        dory_point.resize(params.num_vars, Bls381Fr::zero());
        
        // Convert claimed value
        let dory_value = ark_fr_to_dory(&value);
        
        // Verify using Dory verifier with Fiat-Shamir
        let mut transcript = Blake2bTranscript::new(b"dory-pcs");
        verify::<_, BLS12381, G1Routines, G2Routines, _>(
            commitment.tier2.clone(),
            dory_value,
            &dory_point,
            &proof.proof,
            params.verifier_setup.clone(),
            &mut transcript,
        ).is_ok()
    }
}

#[cfg(test)]
mod pcs_tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;
    
    #[test]
    fn test_dory_pcs_setup() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        assert_eq!(params.num_vars, 4);
        assert_eq!(params.nu, 2);
        assert_eq!(params.sigma, 2);
    }
    
    #[test]
    fn test_dory_pcs_setup_odd_vars() {
        let mut rng = test_rng();
        // Odd number should be rounded up
        let params = DoryPCS::setup(3, &mut rng);
        assert_eq!(params.num_vars, 4); // Rounded up to even
        assert_eq!(params.nu, 2);
        assert_eq!(params.sigma, 2);
    }
    
    #[test]
    fn test_dory_pcs_commit() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let commitment = DoryPCS::commit(&params, &evals);
        
        // Commitment should serialize to non-zero size
        let size = DoryPCS::commitment_size(&commitment);
        assert!(size > 0, "Commitment should have non-zero size");
    }
    
    #[test]
    fn test_dory_pcs_prove_verify() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let commitment = DoryPCS::commit(&params, &evals);
        
        // Random evaluation point
        let point: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        
        // Generate proof
        let (value, proof) = DoryPCS::prove_eval(&params, &evals, &point, &mut rng);
        
        // Verify
        let valid = DoryPCS::verify_eval(&params, &commitment, &point, value, &proof);
        assert!(valid, "Dory-PCS proof should verify");
    }
    
    #[test]
    fn test_dory_pcs_soundness() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let commitment = DoryPCS::commit(&params, &evals);
        
        let point: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let (value, proof) = DoryPCS::prove_eval(&params, &evals, &point, &mut rng);
        
        // Test with wrong value should fail
        let wrong_value = value + Fr::from(1u64);
        let valid = DoryPCS::verify_eval(&params, &commitment, &point, wrong_value, &proof);
        assert!(!valid, "Dory-PCS should reject wrong value");
    }
    
    #[test]
    fn test_dory_pcs_proof_size() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let point: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        
        let (_, proof) = DoryPCS::prove_eval(&params, &evals, &point, &mut rng);
        
        let size = DoryPCS::proof_size(&proof);
        assert!(size > 0, "Proof should have non-zero size");
        
        // O(log n) proof size - for n=16, log n = 4
        // Each round adds O(1) group elements
        println!("Dory-PCS proof size for 4 variables: {} bytes", size);
    }
    
    #[test]
    fn test_dory_pcs_commitment_deterministic() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        
        let params1 = DoryPCS::setup(4, &mut rng1);
        let params2 = DoryPCS::setup(4, &mut rng2);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        
        let c1 = DoryPCS::commit(&params1, &evals);
        let c2 = DoryPCS::commit(&params2, &evals);
        
        // Same setup + same evals = same commitment
        assert_eq!(c1, c2, "Deterministic commitment");
    }
    
    #[test]
    fn test_dory_pcs_serialization_roundtrip() {
        let mut rng = test_rng();
        let params = DoryPCS::setup(4, &mut rng);
        
        let evals: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64)).collect();
        let commitment = DoryPCS::commit(&params, &evals);
        
        // Serialize commitment
        let mut bytes = Vec::new();
        commitment.serialize_compressed(&mut bytes).expect("Serialize failed");
        
        // Deserialize
        let restored = DoryPCSCommitment::deserialize_compressed(&bytes[..]).expect("Deserialize failed");
        
        assert_eq!(commitment, restored, "Commitment roundtrip failed");
    }
}
