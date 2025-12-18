//! Bilinear Inner Product Proof (BIPP)
//!
//! Proves y = ⟨Z, v⟩ where:
//! - Z ∈ G₁^n (vector of group elements)
//! - v ∈ F^n (vector of field elements)
//! - y ∈ G₁ (inner product result = Σ v_i · Z_i)
//!
//! Based on Bünz et al. generalization of Bulletproofs for bilinear groups.
//! Used in Kopis-PC for the "outer product" commitment aggregation.
//!
//! Commitment: C = Π e(Z_i, H_i) · e(y, U)
//! After log(n) rounds, reduces to verifiable claim.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup, CurveGroup};
use ark_ff::{Field, PrimeField, Zero, One};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;
use crate::utils::msm::msm;

type GT = <Bls12_381 as Pairing>::TargetField;

/// Public parameters for BIPP
#[derive(Clone, Debug)]
pub struct BippParams {
    /// Generators H_0, ..., H_{n-1} in G₂
    pub h_vec: Vec<G2Projective>,
    /// Generator U in G₂ for the inner product term
    pub u: G2Projective,
}

impl BippParams {
    /// Setup with n generators in G₂
    pub fn new(n: usize) -> Self {
        let base_g2 = G2Projective::generator();
        
        let mut h_vec = Vec::with_capacity(n);
        for i in 0..n {
            h_vec.push(base_g2 * Fr::from((i + 1) as u64));
        }
        
        let u = base_g2 * Fr::from((n + 1) as u64);
        
        Self { h_vec, u }
    }
    /// Vector-only commitment according to paper §4 (Definition 3.20):
    /// C = Π e(Z_i, H_i)
    /// 
    /// This commits ONLY to the vector Z, without any inner product term.
    /// The inner product is proved later in BIPP.Eval.
    pub fn commit_vector(&self, z: &[G1Projective]) -> GT {
        let n = z.len();
        assert!(n <= self.h_vec.len());
        
        let g1_affine: Vec<G1Affine> = z.iter().map(|p| p.into_affine()).collect();
        let g2_affine: Vec<G2Affine> = self.h_vec[..n].iter().map(|p| p.into_affine()).collect();
        
        Bls12_381::multi_pairing(&g1_affine, &g2_affine).0
    }

    /// Full commitment with inner product: C = Π e(Z_i, H_i) · e(y, U)
    /// where y = ⟨Z, v⟩
    /// 
    /// DEPRECATED for Kopis-PC: Use commit_vector() instead.
    /// This is kept for backwards compatibility with existing tests.
    pub fn commit(&self, z: &[G1Projective], v: &[Fr]) -> GT {
        let n = z.len();
        assert_eq!(n, v.len());
        assert!(n <= self.h_vec.len());
        
        let y = bilinear_inner_product(z, v);
        
        let mut g1_affine: Vec<G1Affine> = z.iter().map(|p| p.into_affine()).collect();
        g1_affine.push(y.into_affine());
        
        let mut g2_affine: Vec<G2Affine> = self.h_vec[..n].iter().map(|p| p.into_affine()).collect();
        g2_affine.push(self.u.into_affine());
        
        Bls12_381::multi_pairing(&g1_affine, &g2_affine).0
    }
    
    /// Create commitment from G1 element and scalar v (used in Kopis-PC)
    /// Helper for reconstructing commitment during verification
    pub fn commit_from_g1_and_v(&self, v: &[Fr], g1_elem: &G1Projective) -> GT {
        let n = v.len();
        assert!(n <= self.h_vec.len());
        
        // Compute weighted sum of H generators
        let mut h_combined = G2Projective::zero();
        for i in 0..n {
            h_combined = h_combined + self.h_vec[i] * v[i];
        }
        
        Bls12_381::pairing(g1_elem.into_affine(), h_combined.into_affine()).0
    }
}

/// A BIPP proof
#[derive(Clone, Debug)]
pub struct BippProof {
    /// Left cross-terms from each round (in G_T)
    pub l_vec: Vec<GT>,
    /// Right cross-terms from each round (in G_T)
    pub r_vec: Vec<GT>,
    /// Final Z element after folding
    pub z_final: G1Projective,
    /// Final v element after folding  
    pub v_final: Fr,
}

/// Compute ⟨Z, v⟩ = Σ v_i · Z_i (scalar mult in G₁)
/// Uses Pippenger's MSM for O(n/log n) complexity
pub fn bilinear_inner_product(z: &[G1Projective], v: &[Fr]) -> G1Projective {
    assert_eq!(z.len(), v.len());
    msm(z, v)
}

/// Transcript for BIPP Fiat-Shamir
#[derive(Clone, Debug)]
pub struct BippTranscript {
    state: Vec<u8>,
}

impl BippTranscript {
    pub fn new(label: &[u8]) -> Self {
        Self { state: label.to_vec() }
    }

    pub fn append_gt(&mut self, elem: &GT) {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = Vec::new();
        elem.serialize_compressed(&mut bytes).expect("serialization");
        self.state.extend_from_slice(&bytes);
    }

    pub fn challenge(&mut self) -> Fr {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.state);
        let result = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result[..32]);
        self.state.extend_from_slice(&bytes);
        
        Fr::from_le_bytes_mod_order(&bytes)
    }
}

/// BIPP Prover
pub struct BippProver;

impl BippProver {
    /// Prove for commit() style commitment (includes inner product in L/R)
    /// Use this with BippVerifier::verify()
    pub fn prove<R: RngCore>(
        params: &BippParams,
        z: &[G1Projective],
        v: &[Fr],
        transcript: &mut BippTranscript,
        _rng: &mut R,
    ) -> BippProof {
        let n = z.len();
        assert!(n.is_power_of_two());
        assert_eq!(z.len(), v.len());
        
        let num_rounds = (n as f64).log2() as usize;
        
        let mut l_vec = Vec::with_capacity(num_rounds);
        let mut r_vec = Vec::with_capacity(num_rounds);
        
        let mut z_curr = z.to_vec();
        let mut v_curr = v.to_vec();
        let mut h_curr = params.h_vec[..n].to_vec();
        
        for _round in 0..num_rounds {
            let half = z_curr.len() / 2;
            
            let (z_lo, z_hi) = z_curr.split_at(half);
            let (v_lo, v_hi) = v_curr.split_at(half);
            let (h_lo, h_hi) = h_curr.split_at(half);
            
            // L: cross terms from (Z_lo, v_hi, H_hi)
            // L = Π e(Z_lo[i], H_hi[i]) · e(⟨Z_lo, v_hi⟩, U)
            let y_l = bilinear_inner_product(z_lo, v_hi);
            let mut l_g1: Vec<G1Affine> = z_lo.iter().map(|p| p.into_affine()).collect();
            l_g1.push(y_l.into_affine());
            let mut l_g2: Vec<G2Affine> = h_hi.iter().map(|p| p.into_affine()).collect();
            l_g2.push(params.u.into_affine());
            let l = Bls12_381::multi_pairing(&l_g1, &l_g2).0;
            
            // R: cross terms from (Z_hi, v_lo, H_lo)
            // R = Π e(Z_hi[i], H_lo[i]) · e(⟨Z_hi, v_lo⟩, U)
            let y_r = bilinear_inner_product(z_hi, v_lo);
            let mut r_g1: Vec<G1Affine> = z_hi.iter().map(|p| p.into_affine()).collect();
            r_g1.push(y_r.into_affine());
            let mut r_g2: Vec<G2Affine> = h_lo.iter().map(|p| p.into_affine()).collect();
            r_g2.push(params.u.into_affine());
            let r = Bls12_381::multi_pairing(&r_g1, &r_g2).0;
            
            l_vec.push(l);
            r_vec.push(r);
            
            transcript.append_gt(&l);
            transcript.append_gt(&r);
            let x = transcript.challenge();
            let x_inv = x.inverse().expect("challenge non-zero");
            
            // Fold: Z' = x·Z_lo + x^{-1}·Z_hi
            //       v' = x^{-1}·v_lo + x·v_hi
            //       H' = x^{-1}·H_lo + x·H_hi
            let mut z_new = Vec::with_capacity(half);
            let mut v_new = Vec::with_capacity(half);
            let mut h_new = Vec::with_capacity(half);
            
            for i in 0..half {
                z_new.push(z_lo[i] * x + z_hi[i] * x_inv);
                v_new.push(v_lo[i] * x_inv + v_hi[i] * x);
                h_new.push(h_lo[i] * x_inv + h_hi[i] * x);
            }
            
            z_curr = z_new;
            v_curr = v_new;
            h_curr = h_new;
        }
        
        BippProof {
            l_vec,
            r_vec,
            z_final: z_curr[0],
            v_final: v_curr[0],
        }
    }
    
    /// Prove for commit_vector() style commitment (paper §3.7, §4)
    /// 
    /// According to Definition 3.20 and Bünz et al.:
    /// - C = Π e(Z[i], H[i]) is the commitment (no inner product term)
    /// - The verifier will add e(y, U) where y = ⟨Z, V⟩
    /// - L/R MUST include the inner product cross-terms for correct folding
    /// 
    /// L = Π e(Z_lo[i], H_hi[i]) · e(⟨Z_lo, V_hi⟩, U)
    /// R = Π e(Z_hi[i], H_lo[i]) · e(⟨Z_hi, V_lo⟩, U)
    /// 
    /// Use this with BippVerifier::verify_eval()
    pub fn prove_eval<R: RngCore>(
        params: &BippParams,
        z: &[G1Projective],
        v: &[Fr],
        transcript: &mut BippTranscript,
        _rng: &mut R,
    ) -> BippProof {
        let n = z.len();
        assert!(n.is_power_of_two());
        assert_eq!(z.len(), v.len());
        
        let num_rounds = (n as f64).log2() as usize;
        
        let mut l_vec = Vec::with_capacity(num_rounds);
        let mut r_vec = Vec::with_capacity(num_rounds);
        
        let mut z_curr = z.to_vec();
        let mut v_curr = v.to_vec();
        let mut h_curr = params.h_vec[..n].to_vec();
        
        for _round in 0..num_rounds {
            let half = z_curr.len() / 2;
            
            let (z_lo, z_hi) = z_curr.split_at(half);
            let (v_lo, v_hi) = v_curr.split_at(half);
            let (h_lo, h_hi) = h_curr.split_at(half);
            
            // L: cross terms from (Z_lo, V_hi, H_hi)
            // L = Π e(Z_lo[i], H_hi[i]) · e(⟨Z_lo, V_hi⟩, U)
            // This includes the inner product cross-term for correct folding
            let y_l = bilinear_inner_product(z_lo, v_hi);  // ⟨Z_lo, V_hi⟩ ∈ G_1
            let mut l_g1: Vec<G1Affine> = z_lo.iter().map(|p| p.into_affine()).collect();
            l_g1.push(y_l.into_affine());
            let mut l_g2: Vec<G2Affine> = h_hi.iter().map(|p| p.into_affine()).collect();
            l_g2.push(params.u.into_affine());
            let l = Bls12_381::multi_pairing(&l_g1, &l_g2).0;
            
            // R: cross terms from (Z_hi, V_lo, H_lo)
            // R = Π e(Z_hi[i], H_lo[i]) · e(⟨Z_hi, V_lo⟩, U)
            let y_r = bilinear_inner_product(z_hi, v_lo);  // ⟨Z_hi, V_lo⟩ ∈ G_1
            let mut r_g1: Vec<G1Affine> = z_hi.iter().map(|p| p.into_affine()).collect();
            r_g1.push(y_r.into_affine());
            let mut r_g2: Vec<G2Affine> = h_lo.iter().map(|p| p.into_affine()).collect();
            r_g2.push(params.u.into_affine());
            let r = Bls12_381::multi_pairing(&r_g1, &r_g2).0;
            
            l_vec.push(l);
            r_vec.push(r);
            
            transcript.append_gt(&l);
            transcript.append_gt(&r);
            let x = transcript.challenge();
            let x_inv = x.inverse().expect("challenge non-zero");
            
            // Fold vectors: Z' = x·Z_lo + x^{-1}·Z_hi
            //               V' = x^{-1}·V_lo + x·V_hi
            //               H' = x^{-1}·H_lo + x·H_hi
            let mut z_new = Vec::with_capacity(half);
            let mut v_new = Vec::with_capacity(half);
            let mut h_new = Vec::with_capacity(half);
            
            for i in 0..half {
                z_new.push(z_lo[i] * x + z_hi[i] * x_inv);
                v_new.push(v_lo[i] * x_inv + v_hi[i] * x);
                h_new.push(h_lo[i] * x_inv + h_hi[i] * x);
            }
            
            z_curr = z_new;
            v_curr = v_new;
            h_curr = h_new;
        }
        
        BippProof {
            l_vec,
            r_vec,
            z_final: z_curr[0],
            v_final: v_curr[0],
        }
    }
}

/// BIPP Verifier
pub struct BippVerifier;

impl BippVerifier {
    /// Verify BIPP proof for commit() style commitment (includes inner product term)
    /// 
    /// This is the original verify function for backwards compatibility.
    pub fn verify(
        params: &BippParams,
        commitment: &GT,
        proof: &BippProof,
        transcript: &mut BippTranscript,
    ) -> bool {
        let num_rounds = proof.l_vec.len();
        let n = 1usize << num_rounds;
        
        if proof.l_vec.len() != proof.r_vec.len() {
            return false;
        }
        if n > params.h_vec.len() {
            return false;
        }
        
        // Collect challenges
        let mut challenges = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            transcript.append_gt(&proof.l_vec[i]);
            transcript.append_gt(&proof.r_vec[i]);
            challenges.push(transcript.challenge());
        }
        
        // Compute C' = C · Π L_j^{x_j²} · Π R_j^{x_j^{-2}}
        let mut c_prime = *commitment;
        for j in 0..num_rounds {
            let x = challenges[j];
            let x_sq = x.square();
            let x_inv_sq = x_sq.inverse().expect("challenge non-zero");
            
            c_prime = c_prime * proof.l_vec[j].pow(x_sq.into_bigint());
            c_prime = c_prime * proof.r_vec[j].pow(x_inv_sq.into_bigint());
        }
        
        // Compute H' = Σ s_h[i] · H[i]
        // s_h[i] = Π (bit=0: x_j^{-1}, bit=1: x_j)
        let mut s_h = vec![Fr::one(); n];
        for j in 0..num_rounds {
            let x = challenges[j];
            let x_inv = x.inverse().expect("challenge non-zero");
            let bit_pos = num_rounds - 1 - j;
            
            for i in 0..n {
                let bit = (i >> bit_pos) & 1;
                if bit == 0 {
                    s_h[i] *= x_inv;
                } else {
                    s_h[i] *= x;
                }
            }
        }
        
        let mut h_prime = G2Projective::zero();
        for i in 0..n {
            h_prime = h_prime + params.h_vec[i] * s_h[i];
        }
        
        // Final: C' should equal e(z_final, h_prime) · e(z_final·v_final, U)
        let y_final = proof.z_final * proof.v_final;
        let check_g1 = vec![proof.z_final.into_affine(), y_final.into_affine()];
        let check_g2 = vec![h_prime.into_affine(), params.u.into_affine()];
        let expected = Bls12_381::multi_pairing(&check_g1, &check_g2).0;
        
        c_prime == expected
    }
    
    /// Verify BIPP.Eval for vector-only commitment (paper §3.7, Definition 3.20)
    /// 
    /// According to the paper and Bünz et al.:
    /// - C = Π e(Z[i], H[i]) is the vector-only commitment
    /// - y_out = ⟨Z, V⟩ is the claimed inner product
    /// - The verifier ADDS e(y_out, U) to C before applying L/R
    /// 
    /// Verification:
    /// C · e(y_out, U) · Π L_j^{x_j²} · Π R_j^{x_j^{-2}} = e(z_final, h_prime) · e(y_final, U)
    /// 
    /// where y_final = z_final · v_final
    pub fn verify_eval(
        params: &BippParams,
        commitment: &GT,  // C = Π e(Z[i], H[i]) (vector-only commitment)
        y_out: &G1Projective,  // Claimed inner product y = ⟨Z, V⟩ ∈ G_1
        proof: &BippProof,
        transcript: &mut BippTranscript,
    ) -> bool {
        let num_rounds = proof.l_vec.len();
        let n = 1usize << num_rounds;
        
        if proof.l_vec.len() != proof.r_vec.len() {
            return false;
        }
        if n > params.h_vec.len() {
            return false;
        }
        
        // Collect challenges (must match prove_eval)
        let mut challenges = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            transcript.append_gt(&proof.l_vec[i]);
            transcript.append_gt(&proof.r_vec[i]);
            challenges.push(transcript.challenge());
        }
        
        // Key step: ADD e(y_out, U) to the commitment
        // This transforms vector-only commitment to full commitment:
        // C_full = C · e(y_out, U) = Π e(Z[i], H[i]) · e(⟨Z,V⟩, U)
        let y_commitment = Bls12_381::pairing(
            y_out.into_affine(),
            params.u.into_affine()
        ).0;
        let mut c_prime = *commitment * y_commitment;
        
        // Apply L/R terms: C' = C_full · Π L_j^{x_j²} · Π R_j^{x_j^{-2}}
        for j in 0..num_rounds {
            let x = challenges[j];
            let x_sq = x.square();
            let x_inv_sq = x_sq.inverse().expect("challenge non-zero");
            
            c_prime = c_prime * proof.l_vec[j].pow(x_sq.into_bigint());
            c_prime = c_prime * proof.r_vec[j].pow(x_inv_sq.into_bigint());
        }
        
        // Compute H' = Σ s_h[i] · H[i]
        let mut s_h = vec![Fr::one(); n];
        for j in 0..num_rounds {
            let x = challenges[j];
            let x_inv = x.inverse().expect("challenge non-zero");
            let bit_pos = num_rounds - 1 - j;
            
            for i in 0..n {
                let bit = (i >> bit_pos) & 1;
                if bit == 0 {
                    s_h[i] *= x_inv;
                } else {
                    s_h[i] *= x;
                }
            }
        }
        
        let mut h_prime = G2Projective::zero();
        for i in 0..n {
            h_prime = h_prime + params.h_vec[i] * s_h[i];
        }
        
        // Final verification:
        // C' should equal e(z_final, h_prime) · e(y_final, U)
        // where y_final = z_final · v_final is the folded inner product
        let y_final = proof.z_final * proof.v_final;
        
        let expected_g1 = vec![proof.z_final.into_affine(), y_final.into_affine()];
        let expected_g2 = vec![h_prime.into_affine(), params.u.into_affine()];
        let expected_c = Bls12_381::multi_pairing(&expected_g1, &expected_g2).0;
        
        c_prime == expected_c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;

    #[test]
    fn bilinear_inner_product_basic() {
        let g = G1Projective::generator();
        let z = vec![g, g * Fr::from(2u64)];
        let v = vec![Fr::from(3u64), Fr::from(4u64)];
        let result = bilinear_inner_product(&z, &v);
        assert_eq!(result, g * Fr::from(11u64));
    }

    #[test]
    fn bipp_params_creation() {
        let n = 4;
        let params = BippParams::new(n);
        assert_eq!(params.h_vec.len(), n);
    }

    #[test]
    fn bipp_prove_basic() {
        let mut rng = test_rng();
        let n = 2;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let mut transcript = BippTranscript::new(b"bipp");
        let proof = BippProver::prove(&params, &z, &v, &mut transcript, &mut rng);
        
        assert_eq!(proof.l_vec.len(), 1);
    }

    #[test]
    fn bipp_proof_size_logarithmic() {
        let mut rng = test_rng();
        let g = G1Projective::generator();
        
        for log_n in 1..=4 {
            let n = 1 << log_n;
            let params = BippParams::new(n);
            
            let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
            let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            let mut transcript = BippTranscript::new(b"bipp");
            let proof = BippProver::prove(&params, &z, &v, &mut transcript, &mut rng);
            
            assert_eq!(proof.l_vec.len(), log_n);
        }
    }

    #[test]
    fn bipp_deterministic() {
        let mut rng = test_rng();
        let n = 4;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (1..=n as u64).map(|i| g * Fr::from(i)).collect();
        let v: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        
        let mut t1 = BippTranscript::new(b"bipp");
        let proof1 = BippProver::prove(&params, &z, &v, &mut t1, &mut rng);
        
        let mut t2 = BippTranscript::new(b"bipp");
        let proof2 = BippProver::prove(&params, &z, &v, &mut t2, &mut rng);
        
        assert_eq!(proof1.z_final, proof2.z_final);
        assert_eq!(proof1.v_final, proof2.v_final);
    }

    #[test]
    fn bipp_verify_n2() {
        let mut rng = test_rng();
        let n = 2;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit(&z, &v);
        
        let mut pt = BippTranscript::new(b"bipp");
        let proof = BippProver::prove(&params, &z, &v, &mut pt, &mut rng);
        
        let mut vt = BippTranscript::new(b"bipp");
        assert!(BippVerifier::verify(&params, &c, &proof, &mut vt));
    }

    #[test]
    fn bipp_verify_n4() {
        let mut rng = test_rng();
        let n = 4;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit(&z, &v);
        
        let mut pt = BippTranscript::new(b"bipp");
        let proof = BippProver::prove(&params, &z, &v, &mut pt, &mut rng);
        
        let mut vt = BippTranscript::new(b"bipp");
        assert!(BippVerifier::verify(&params, &c, &proof, &mut vt));
    }

    #[test]
    fn bipp_verify_n16() {
        let mut rng = test_rng();
        let n = 16;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit(&z, &v);
        
        let mut pt = BippTranscript::new(b"bipp");
        let proof = BippProver::prove(&params, &z, &v, &mut pt, &mut rng);
        
        let mut vt = BippTranscript::new(b"bipp");
        assert!(BippVerifier::verify(&params, &c, &proof, &mut vt));
    }

    #[test]
    fn bipp_reject_tampered() {
        let mut rng = test_rng();
        let n = 4;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit(&z, &v);
        
        let mut pt = BippTranscript::new(b"bipp");
        let mut proof = BippProver::prove(&params, &z, &v, &mut pt, &mut rng);
        
        // Tamper
        proof.z_final = proof.z_final + g;
        
        let mut vt = BippTranscript::new(b"bipp");
        assert!(!BippVerifier::verify(&params, &c, &proof, &mut vt));
    }

    #[test]
    fn bipp_completeness_extensive() {
        let mut rng = test_rng();
        let g = G1Projective::generator();
        
        for _ in 0..10 {
            let log_n = (rng.next_u32() % 4 + 1) as usize;
            let n = 1 << log_n;
            
            let params = BippParams::new(n);
            
            let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
            let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            let c = params.commit(&z, &v);
            
            let mut pt = BippTranscript::new(b"bipp");
            let proof = BippProver::prove(&params, &z, &v, &mut pt, &mut rng);
            
            let mut vt = BippTranscript::new(b"bipp");
            assert!(BippVerifier::verify(&params, &c, &proof, &mut vt), "failed n={}", n);
        }
    }
    
    // ========================================================================
    // Tests for commit_vector + prove_eval + verify_eval (paper §4 style)
    // ========================================================================
    
    #[test]
    fn bipp_eval_n2() {
        let mut rng = test_rng();
        let n = 2;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Vector-only commitment (paper style)
        let c = params.commit_vector(&z);
        
        // Compute y_out = ⟨Z, V⟩
        let y_out = bilinear_inner_product(&z, &v);
        
        // Generate proof with prove_eval
        let mut pt = BippTranscript::new(b"bipp_eval");
        let proof = BippProver::prove_eval(&params, &z, &v, &mut pt, &mut rng);
        
        // Verify with verify_eval
        let mut vt = BippTranscript::new(b"bipp_eval");
        let result = BippVerifier::verify_eval(&params, &c, &y_out, &proof, &mut vt);
        assert!(result, "BIPP eval verify failed for n=2");
    }
    
    #[test]
    fn bipp_eval_n4() {
        let mut rng = test_rng();
        let n = 4;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit_vector(&z);
        let y_out = bilinear_inner_product(&z, &v);
        
        let mut pt = BippTranscript::new(b"bipp_eval");
        let proof = BippProver::prove_eval(&params, &z, &v, &mut pt, &mut rng);
        
        let mut vt = BippTranscript::new(b"bipp_eval");
        let result = BippVerifier::verify_eval(&params, &c, &y_out, &proof, &mut vt);
        assert!(result, "BIPP eval verify failed for n=4");
    }
    
    #[test]
    fn bipp_eval_extensive() {
        let mut rng = test_rng();
        let g = G1Projective::generator();
        
        for log_n in 1..=4 {
            let n = 1 << log_n;
            let params = BippParams::new(n);
            
            let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
            let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            let c = params.commit_vector(&z);
            let y_out = bilinear_inner_product(&z, &v);
            
            let mut pt = BippTranscript::new(b"bipp_eval");
            let proof = BippProver::prove_eval(&params, &z, &v, &mut pt, &mut rng);
            
            let mut vt = BippTranscript::new(b"bipp_eval");
            let result = BippVerifier::verify_eval(&params, &c, &y_out, &proof, &mut vt);
            assert!(result, "BIPP eval verify failed for n={}", n);
        }
    }
    
    #[test]
    fn bipp_eval_wrong_y_rejected() {
        let mut rng = test_rng();
        let n = 4;
        
        let params = BippParams::new(n);
        let g = G1Projective::generator();
        
        let z: Vec<G1Projective> = (0..n).map(|_| g * Fr::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let c = params.commit_vector(&z);
        let y_out = bilinear_inner_product(&z, &v);
        
        // Generate valid proof
        let mut pt = BippTranscript::new(b"bipp_eval");
        let proof = BippProver::prove_eval(&params, &z, &v, &mut pt, &mut rng);
        
        // Try to verify with WRONG y_out
        let wrong_y_out = y_out + g; // Add generator to corrupt
        let mut vt = BippTranscript::new(b"bipp_eval");
        let result = BippVerifier::verify_eval(&params, &c, &wrong_y_out, &proof, &mut vt);
        assert!(!result, "BIPP eval should reject wrong y_out");
    }
}
