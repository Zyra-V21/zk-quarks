//! Hyrax-style Inner Product Proof (IPP)
//!
//! Based on Spartan2's InnerProductArgumentLinear and paper Definition 3.17.
//!
//! This IPP is designed to prove `c = ⟨a, b⟩` where:
//! - `a ∈ F^n` is committed (prover's witness)
//! - `b ∈ F^n` is PUBLIC (known to both parties)
//! - `c ∈ F` is the claimed inner product
//!
//! This differs from Bulletproofs-style IPP where both vectors are private.
//!
//! Protocol (from Spartan2 comments):
//! ```text
//! Instance: C_a, C_c, b_vec
//! Witness: a_vec, r_a, r_c
//! Satisfies if: C_a = Com(a_vec, r_a), C_c = Com(c, r_c), and c = ⟨a_vec, b_vec⟩
//!
//! P: samples d_vec, r_δ, r_β, and sends:
//!    δ ← Com(d_vec, r_δ)
//!    β ← Com(⟨b_vec, d_vec⟩, r_β)
//!
//! V: sends challenge r
//!
//! P: sends:
//!    z_vec ← r * a_vec + d_vec
//!    z_δ ← r * r_a + r_δ
//!    z_β ← r * r_c + r_β
//!
//! V: checks:
//!    r * C_a + δ =? Com(z_vec, z_δ)
//!    r * C_c + β =? Com(⟨z_vec, b_vec⟩, z_β)
//! ```

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::Group;
use ark_ff::{Zero, UniformRand};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use crate::utils::msm::msm;

/// Compute inner product ⟨a, b⟩
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(ai, bi)| *ai * *bi).sum()
}

/// Public parameters for Hyrax-style IPP
/// 
/// Uses Pedersen-style commitment: C = ⟨a, G⟩ + r·H
#[derive(Clone, Debug)]
pub struct HyraxIppParams {
    /// Generators G_0, ..., G_{n-1} for vector commitment
    pub g_vec: Vec<G1Projective>,
    /// Blinding generator H
    pub h: G1Projective,
}

impl HyraxIppParams {
    /// Setup with n generators
    pub fn new(n: usize) -> Self {
        let base = G1Projective::generator();
        
        // Generate distinct generators using deterministic method
        // In production, use hash-to-curve
        let mut g_vec = Vec::with_capacity(n);
        for i in 0..n {
            g_vec.push(base * Fr::from((i + 1) as u64));
        }
        
        // Blinding generator (independent from G_vec)
        let h = base * Fr::from((n + 1) as u64);
        
        Self { g_vec, h }
    }
    
    /// Commit to a vector: C = ⟨a, G⟩ + r·H
    /// 
    /// Paper Definition 3.17: IPP.Commit receives ONE vector
    pub fn commit(&self, a: &[Fr], blinding: &Fr) -> G1Projective {
        assert!(a.len() <= self.g_vec.len());
        let n = a.len();
        
        // C = Σ a[i]·G[i] + r·H
        let mut c = msm(&self.g_vec[..n], a);
        c = c + self.h * blinding;
        c
    }
    
    /// Commit without blinding (for non-hiding version)
    pub fn commit_no_blind(&self, a: &[Fr]) -> G1Projective {
        self.commit(a, &Fr::zero())
    }
}

/// Instance for Hyrax IPP
/// 
/// Public inputs known to both prover and verifier:
/// - `comm_a`: Commitment to vector a
/// - `b_vec`: The PUBLIC vector b
/// - `comm_c`: Commitment to the claimed inner product c
#[derive(Clone, Debug)]
pub struct HyraxIppInstance {
    /// Commitment to the private vector a: C_a = Com(a, r_a)
    pub comm_a: G1Projective,
    /// Public vector b (known to verifier)
    pub b_vec: Vec<Fr>,
    /// Commitment to the claimed value c: C_c = Com(c, r_c)
    pub comm_c: G1Projective,
}

/// Witness for Hyrax IPP
/// 
/// Private inputs known only to prover
#[derive(Clone, Debug)]
pub struct HyraxIppWitness {
    /// The private vector a
    pub a_vec: Vec<Fr>,
    /// Blinding for commitment to a
    pub r_a: Fr,
    /// The claimed inner product c = ⟨a, b⟩
    pub c: Fr,
    /// Blinding for commitment to c
    pub r_c: Fr,
}

/// Hyrax IPP Proof (linear size)
/// 
/// This is a sigma-protocol proof, not logarithmic like Bulletproofs.
/// Size is O(n) but verification is O(n) field ops + 2 MSMs.
#[derive(Clone, Debug)]
pub struct HyraxIppProof {
    /// δ = Com(d_vec, r_δ)
    pub delta: G1Projective,
    /// β = Com(⟨b, d⟩, r_β)
    pub beta: G1Projective,
    /// z_vec = r·a + d
    pub z_vec: Vec<Fr>,
    /// z_δ = r·r_a + r_δ
    pub z_delta: Fr,
    /// z_β = r·r_c + r_β
    pub z_beta: Fr,
}

/// Transcript for Fiat-Shamir
#[derive(Clone, Debug)]
pub struct HyraxIppTranscript {
    state: Vec<u8>,
}

impl HyraxIppTranscript {
    pub fn new(label: &[u8]) -> Self {
        Self { state: label.to_vec() }
    }
    
    pub fn append_point(&mut self, point: &G1Projective) {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        point.serialize_compressed(&mut bytes).expect("serialization");
        self.state.extend_from_slice(&bytes);
    }
    
    pub fn append_scalars(&mut self, scalars: &[Fr]) {
        use ark_serialize::CanonicalSerialize;
        for s in scalars {
            let mut bytes = Vec::new();
            s.serialize_compressed(&mut bytes).expect("serialization");
            self.state.extend_from_slice(&bytes);
        }
    }
    
    pub fn challenge(&mut self) -> Fr {
        use ark_ff::PrimeField;
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(&self.state);
        let hash = hasher.finalize();
        self.state = hash.to_vec();
        
        Fr::from_le_bytes_mod_order(&hash)
    }
}

/// Hyrax IPP Prover
pub struct HyraxIppProver;

impl HyraxIppProver {
    /// Prove that c = ⟨a, b⟩ given:
    /// - Commitment C_a to private vector a
    /// - Public vector b
    /// - Commitment C_c to claimed value c
    pub fn prove<R: RngCore>(
        params: &HyraxIppParams,
        instance: &HyraxIppInstance,
        witness: &HyraxIppWitness,
        transcript: &mut HyraxIppTranscript,
        rng: &mut R,
    ) -> HyraxIppProof {
        let n = witness.a_vec.len();
        assert_eq!(n, instance.b_vec.len());
        
        // Absorb instance
        transcript.append_point(&instance.comm_a);
        transcript.append_point(&instance.comm_c);
        transcript.append_scalars(&instance.b_vec);
        
        // Sample random d_vec, r_δ, r_β
        let d_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        let r_delta = Fr::rand(rng);
        let r_beta = Fr::rand(rng);
        
        // δ = Com(d_vec, r_δ)
        let delta = params.commit(&d_vec, &r_delta);
        
        // β = Com(⟨b, d⟩, r_β) - commitment to the "cross-term"
        let b_dot_d = inner_product(&instance.b_vec, &d_vec);
        // Use single-element commitment: β = b_dot_d·G[0] + r_β·H
        // Or equivalently: β = G[0]·b_dot_d + H·r_β
        let beta = params.g_vec[0] * b_dot_d + params.h * r_beta;
        
        // Add to transcript and get challenge
        transcript.append_point(&delta);
        transcript.append_point(&beta);
        let r = transcript.challenge();
        
        // Compute responses
        // z_vec = r·a + d
        let z_vec: Vec<Fr> = witness.a_vec.iter()
            .zip(d_vec.iter())
            .map(|(ai, di)| r * *ai + *di)
            .collect();
        
        // z_δ = r·r_a + r_δ
        let z_delta = r * witness.r_a + r_delta;
        
        // z_β = r·r_c + r_β
        let z_beta = r * witness.r_c + r_beta;
        
        HyraxIppProof {
            delta,
            beta,
            z_vec,
            z_delta,
            z_beta,
        }
    }
}

/// Hyrax IPP Verifier
pub struct HyraxIppVerifier;

impl HyraxIppVerifier {
    /// Verify that the proof is valid
    /// 
    /// Checks:
    /// 1. r·C_a + δ = Com(z_vec, z_δ)
    /// 2. r·C_c + β = Com(⟨z_vec, b⟩, z_β)
    pub fn verify(
        params: &HyraxIppParams,
        instance: &HyraxIppInstance,
        proof: &HyraxIppProof,
        transcript: &mut HyraxIppTranscript,
    ) -> bool {
        let n = instance.b_vec.len();
        
        if proof.z_vec.len() != n {
            return false;
        }
        if n > params.g_vec.len() {
            return false;
        }
        
        // Reconstruct challenge
        transcript.append_point(&instance.comm_a);
        transcript.append_point(&instance.comm_c);
        transcript.append_scalars(&instance.b_vec);
        transcript.append_point(&proof.delta);
        transcript.append_point(&proof.beta);
        let r = transcript.challenge();
        
        // Check 1: r·C_a + δ = Com(z_vec, z_δ)
        let lhs1 = instance.comm_a * r + proof.delta;
        let rhs1 = params.commit(&proof.z_vec, &proof.z_delta);
        
        if lhs1 != rhs1 {
            return false;
        }
        
        // Check 2: r·C_c + β = Com(⟨z_vec, b⟩, z_β)
        let lhs2 = instance.comm_c * r + proof.beta;
        let z_dot_b = inner_product(&proof.z_vec, &instance.b_vec);
        let rhs2 = params.g_vec[0] * z_dot_b + params.h * proof.z_beta;
        
        if lhs2 != rhs2 {
            return false;
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    
    #[test]
    fn test_hyrax_ipp_params() {
        let n = 4;
        let params = HyraxIppParams::new(n);
        assert_eq!(params.g_vec.len(), n);
    }
    
    #[test]
    fn test_hyrax_ipp_commit() {
        let mut rng = test_rng();
        let n = 4;
        let params = HyraxIppParams::new(n);
        
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        
        let c1 = params.commit(&a, &r);
        let c2 = params.commit(&a, &r);
        
        // Deterministic
        assert_eq!(c1, c2);
        
        // Different with different blinding
        let c3 = params.commit(&a, &Fr::rand(&mut rng));
        assert_ne!(c1, c3);
    }
    
    #[test]
    fn test_hyrax_ipp_inner_product() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let ip = inner_product(&a, &b);
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(ip, Fr::from(32u64));
    }
    
    #[test]
    fn test_hyrax_ipp_prove_verify() {
        let mut rng = test_rng();
        let n = 4;
        let params = HyraxIppParams::new(n);
        
        // Create witness: private vector a
        let a_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let r_a = Fr::rand(&mut rng);
        
        // Public vector b
        let b_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Compute inner product
        let c = inner_product(&a_vec, &b_vec);
        let r_c = Fr::rand(&mut rng);
        
        // Create commitments
        let comm_a = params.commit(&a_vec, &r_a);
        let comm_c = params.g_vec[0] * c + params.h * r_c;
        
        // Create instance and witness
        let instance = HyraxIppInstance {
            comm_a,
            b_vec: b_vec.clone(),
            comm_c,
        };
        
        let witness = HyraxIppWitness {
            a_vec,
            r_a,
            c,
            r_c,
        };
        
        // Prove
        let mut prove_transcript = HyraxIppTranscript::new(b"hyrax_ipp_test");
        let proof = HyraxIppProver::prove(&params, &instance, &witness, &mut prove_transcript, &mut rng);
        
        // Verify
        let mut verify_transcript = HyraxIppTranscript::new(b"hyrax_ipp_test");
        let valid = HyraxIppVerifier::verify(&params, &instance, &proof, &mut verify_transcript);
        
        assert!(valid, "Valid proof should verify");
    }
    
    #[test]
    fn test_hyrax_ipp_soundness() {
        let mut rng = test_rng();
        let n = 4;
        let params = HyraxIppParams::new(n);
        
        // Create honest witness
        let a_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let r_a = Fr::rand(&mut rng);
        let b_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let c = inner_product(&a_vec, &b_vec);
        let r_c = Fr::rand(&mut rng);
        
        let comm_a = params.commit(&a_vec, &r_a);
        let comm_c = params.g_vec[0] * c + params.h * r_c;
        
        let instance = HyraxIppInstance {
            comm_a,
            b_vec: b_vec.clone(),
            comm_c,
        };
        
        let witness = HyraxIppWitness {
            a_vec,
            r_a,
            c,
            r_c,
        };
        
        // Generate valid proof
        let mut prove_transcript = HyraxIppTranscript::new(b"hyrax_ipp_test");
        let proof = HyraxIppProver::prove(&params, &instance, &witness, &mut prove_transcript, &mut rng);
        
        // Create instance with WRONG c (should fail)
        let wrong_c = c + Fr::from(1u64);
        let wrong_comm_c = params.g_vec[0] * wrong_c + params.h * r_c;
        let wrong_instance = HyraxIppInstance {
            comm_a,
            b_vec,
            comm_c: wrong_comm_c,
        };
        
        let mut verify_transcript = HyraxIppTranscript::new(b"hyrax_ipp_test");
        let valid = HyraxIppVerifier::verify(&params, &wrong_instance, &proof, &mut verify_transcript);
        
        assert!(!valid, "Proof with wrong claimed value should fail");
    }
    
    #[test]
    fn test_hyrax_ipp_extensive() {
        let mut rng = test_rng();
        
        for log_n in 1..=4 {
            let n = 1 << log_n;
            let params = HyraxIppParams::new(n);
            
            let a_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let r_a = Fr::rand(&mut rng);
            let b_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let c = inner_product(&a_vec, &b_vec);
            let r_c = Fr::rand(&mut rng);
            
            let comm_a = params.commit(&a_vec, &r_a);
            let comm_c = params.g_vec[0] * c + params.h * r_c;
            
            let instance = HyraxIppInstance {
                comm_a,
                b_vec: b_vec.clone(),
                comm_c,
            };
            
            let witness = HyraxIppWitness {
                a_vec,
                r_a,
                c,
                r_c,
            };
            
            let mut prove_transcript = HyraxIppTranscript::new(b"hyrax_ipp_extensive");
            let proof = HyraxIppProver::prove(&params, &instance, &witness, &mut prove_transcript, &mut rng);
            
            let mut verify_transcript = HyraxIppTranscript::new(b"hyrax_ipp_extensive");
            let valid = HyraxIppVerifier::verify(&params, &instance, &proof, &mut verify_transcript);
            
            assert!(valid, "Failed for n={}", n);
        }
    }
}

