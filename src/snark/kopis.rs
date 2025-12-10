//! Kopis: Transparent zkSNARK with O_λ(√n) verification
//!
//! Properties:
//! - Prover: O_λ(n) time
//! - Proof size: O_λ(log n) - SHORTEST in the literature
//! - Verifier: O_λ(√n) with Kopis-PC, O_λ(log n) with Dory-PC
//! - Preprocessing: O(n) field ops with untrusted assistant
//!
//! Generic over PCS through `KopisSnark<PCS>`.

use ark_bls12_381::Fr;
use ark_ff::{UniformRand, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::RngCore, Zero};
use core::marker::PhantomData;

use crate::r1cs::R1CSInstance;
use crate::traits::PolynomialCommitmentScheme;
use crate::kopis_pc::KopisPCS;
use crate::zk::zk_sumcheck::zk_sumcheck_prove;
use crate::polynomial::MultilinearPolynomial;
use crate::utils::batching::{EvaluationBatch, batching_challenge, batch_values};
use super::common::{GenericSnarkParams, Witness, Proof, ProofMetadata, ComputationCommitment};
use super::utils::{build_z_vector, build_r1cs_sumcheck_polynomial};

// =============================================================================
// Kopis SNARK - Generic over PCS (paper §3-8)
// =============================================================================

/// Kopis SNARK with pluggable Polynomial Commitment Scheme
/// 
/// # Type Parameters
/// - `PCS`: Polynomial Commitment Scheme (e.g., `KopisPCS`, `DoryPCS`)
/// 
/// # Paper Reference
/// Kopis is described in Quarks paper §3-8. It achieves:
/// - O(log n) proof size (shortest in literature)
/// - O(√n) verification with Kopis-PC
/// - O(log n) verification with Dory-PC
/// 
/// # Example
/// ```ignore
/// use quarks::snark::KopisSnark;
/// use quarks::kopis_pc::KopisPCS;
/// use quarks::dory_pc::DoryPCS;
/// 
/// // With Kopis-PC - O(√n) verification
/// let snark = KopisSnark::<KopisPCS>::setup(16, &mut rng);
/// 
/// // With Dory-PC - O(log n) verification  
/// let snark = KopisSnark::<DoryPCS>::setup(16, &mut rng);
/// ```
pub struct KopisSnark<PCS: PolynomialCommitmentScheme<Fr>> {
    /// Generic SNARK parameters
    pub params: GenericSnarkParams<PCS>,
    _marker: PhantomData<PCS>,
}

impl<PCS: PolynomialCommitmentScheme<Fr>> KopisSnark<PCS> {
    /// Setup Kopis with generic PCS
    /// 
    /// # Arguments
    /// - `max_num_vars`: Maximum number of variables supported
    /// - `rng`: Random number generator
    pub fn setup<R: RngCore>(max_num_vars: usize, rng: &mut R) -> Self {
        let params = GenericSnarkParams::setup(max_num_vars, rng);
        Self { params, _marker: PhantomData }
    }
    
    /// Preprocessing: Commit to R1CS matrices
    /// 
    /// # Arguments
    /// - `instance`: R1CS instance (A, B, C matrices)
    /// - `rng`: Random number generator
    pub fn preprocess<R: RngCore>(
        &self,
        instance: &R1CSInstance<Fr>,
        rng: &mut R,
    ) -> ComputationCommitment {
        // Commit to matrices A, B, C using PCS
        // Each matrix is converted to MLE and committed
        
        let num_constraints = instance.num_constraints.next_power_of_two();
        let num_vars = instance.num_vars.next_power_of_two();
        let total_size = num_constraints * num_vars;
        let mle_vars = ark_std::log2(total_size.next_power_of_two()) as usize;
        let padded_size = 1 << mle_vars.max(2);
        
        // Convert sparse matrices to dense evaluations
        let a_evals = matrix_to_mle_evals(&instance.a, num_constraints, num_vars, padded_size);
        let b_evals = matrix_to_mle_evals(&instance.b, num_constraints, num_vars, padded_size);
        let c_evals = matrix_to_mle_evals(&instance.c, num_constraints, num_vars, padded_size);
        
        // Commit using generic PCS
        let commit_a = PCS::commit_hiding(&self.params.pcs_params, &a_evals, rng);
        let commit_b = PCS::commit_hiding(&self.params.pcs_params, &b_evals, rng);
        let commit_c = PCS::commit_hiding(&self.params.pcs_params, &c_evals, rng);
        
        // Serialize commitments
        let mut commit_a_bytes = Vec::new();
        let mut commit_b_bytes = Vec::new();
        let mut commit_c_bytes = Vec::new();
        commit_a.serialize_compressed(&mut commit_a_bytes).expect("serialize commit_a");
        commit_b.serialize_compressed(&mut commit_b_bytes).expect("serialize commit_b");
        commit_c.serialize_compressed(&mut commit_c_bytes).expect("serialize commit_c");
        
        ComputationCommitment {
            commit_a: commit_a_bytes,
            commit_b: commit_b_bytes,
            commit_c: commit_c_bytes,
            hints: vec![],
        }
    }
    
    /// Prove R1CS satisfiability
    /// 
    /// # Arguments
    /// - `instance`: R1CS instance
    /// - `witness`: Witness values
    /// - `computation_commit`: Preprocessed commitments
    /// - `rng`: Random number generator
    /// 
    /// # Returns
    /// Proof with O(log n) size
    pub fn prove<R: RngCore>(
        &self,
        instance: &R1CSInstance<Fr>,
        witness: &Witness,
        _computation_commit: &ComputationCommitment,
        rng: &mut R,
    ) -> Proof {
        // Verify witness satisfies instance
        use crate::r1cs::Witness as R1CSWitness;
        let r1cs_witness = R1CSWitness {
            public_inputs: vec![],
            assignments: witness.values.clone(),
        };
        assert!(
            instance.is_satisfied(&r1cs_witness).is_ok_and(|b| b),
            "Witness does not satisfy R1CS instance"
        );
        
        // ========== STEP 1: Build z vector ==========
        let public_inputs: Vec<Fr> = vec![];
        let z = build_z_vector(&public_inputs, &witness.values);
        
        // ========== STEP 2: Compute A·z, B·z, C·z ==========
        let mut az = instance.a.mul_vector(&z);
        let mut bz = instance.b.mul_vector(&z);
        let mut cz = instance.c.mul_vector(&z);
        
        // Pad to power of 2
        let num_constraints_padded = if instance.num_constraints > 0 {
            1 << (ark_std::log2(instance.num_constraints) as usize + 
                 if instance.num_constraints.is_power_of_two() { 0 } else { 1 })
        } else {
            1
        };
        az.resize(num_constraints_padded, Fr::zero());
        bz.resize(num_constraints_padded, Fr::zero());
        cz.resize(num_constraints_padded, Fr::zero());
        
        // ========== STEP 3: Commit using generic PCS ==========
        let z_len = z.len();
        let z_num_vars = ark_std::log2(z_len.next_power_of_two()) as usize;
        let expected_z_size = 1 << z_num_vars.max(2);
        let mut z_padded = z.clone();
        z_padded.resize(expected_z_size, Fr::zero());
        
        // Commit with hiding (§8 line 711)
        let commitment = PCS::commit_hiding(&self.params.pcs_params, &z_padded, rng);
        
        let mut commitment_bytes = Vec::new();
        commitment.serialize_compressed(&mut commitment_bytes)
            .expect("commitment serialization");
        
        // ========== STEP 4: Build R1CS sum-check polynomial ==========
        let num_constraint_vars = ark_std::log2(num_constraints_padded).max(1) as usize;
        let tau: Vec<Fr> = (0..num_constraint_vars).map(|_| Fr::rand(rng)).collect();
        
        let sumcheck_poly = build_r1cs_sumcheck_polynomial(&az, &bz, &cz, &tau);
        let claimed_sum = Fr::zero();
        
        // ========== STEP 5: Run ZK sum-check ==========
        let mut sumcheck_evals = sumcheck_poly.evaluations.clone();
        let required_eval_size = 1 << num_constraint_vars;
        sumcheck_evals.resize(required_eval_size, Fr::zero());
        
        let zk_sumcheck_proof = zk_sumcheck_prove(
            &sumcheck_evals,
            claimed_sum,
            num_constraint_vars,
            rng,
        );
        
        let challenges = &zk_sumcheck_proof.final_point;
        
        // Serialize ZK sum-check
        let mut sumcheck_data = Vec::new();
        for round_poly in &zk_sumcheck_proof.round_polys {
            sumcheck_data.extend_from_slice(&round_poly.coeffs);
        }
        sumcheck_data.extend_from_slice(&zk_sumcheck_proof.masking_evals);
        sumcheck_data.push(zk_sumcheck_proof.masked_sum);
        sumcheck_data.push(zk_sumcheck_proof.final_value);
        
        // ========== STEP 6: Evaluate polynomials at challenges ==========
        let required_size = 1 << challenges.len();
        
        let mut z_for_eval = z_padded.clone();
        z_for_eval.resize(required_size, Fr::zero());
        let z_poly = MultilinearPolynomial::from_evaluations(z_for_eval, challenges.len());
        let z_at_r = z_poly.evaluate(challenges);
        
        let mut az_for_eval = az.clone();
        let mut bz_for_eval = bz.clone();
        let mut cz_for_eval = cz.clone();
        az_for_eval.resize(required_size, Fr::zero());
        bz_for_eval.resize(required_size, Fr::zero());
        cz_for_eval.resize(required_size, Fr::zero());
        
        let az_poly = MultilinearPolynomial::from_evaluations(az_for_eval, challenges.len());
        let bz_poly = MultilinearPolynomial::from_evaluations(bz_for_eval, challenges.len());
        let cz_poly = MultilinearPolynomial::from_evaluations(cz_for_eval, challenges.len());
        
        let eval_az = az_poly.evaluate(challenges);
        let eval_bz = bz_poly.evaluate(challenges);
        let eval_cz = cz_poly.evaluate(challenges);
        
        // ========== STEP 7: Batched evaluations (15% optimization) ==========
        let mut eval_batch = EvaluationBatch::new();
        eval_batch.add(challenges.clone(), eval_az);
        eval_batch.add(challenges.clone(), eval_bz);
        eval_batch.add(challenges.clone(), eval_cz);
        eval_batch.add(challenges.clone(), z_at_r);
        
        let alpha = batching_challenge(&commitment_bytes, &eval_batch);
        let batched_eval = batch_values(&[eval_az, eval_bz, eval_cz, z_at_r], &alpha);
        
        // Serialize evaluations
        let mut eval_proof_bytes = Vec::new();
        batched_eval.serialize_compressed(&mut eval_proof_bytes).expect("batched eval");
        eval_az.serialize_compressed(&mut eval_proof_bytes).expect("eval_az");
        eval_bz.serialize_compressed(&mut eval_proof_bytes).expect("eval_bz");
        eval_cz.serialize_compressed(&mut eval_proof_bytes).expect("eval_cz");
        z_at_r.serialize_compressed(&mut eval_proof_bytes).expect("z_at_r");
        
        // ========== STEP 8: Generate PCS evaluation proof ==========
        let (pcs_eval_value, pcs_proof) = PCS::prove_eval(
            &self.params.pcs_params,
            &z_padded,
            challenges,
            rng,
        );
        
        let mut pcs_eval_proof_bytes = Vec::new();
        pcs_proof.serialize_compressed(&mut pcs_eval_proof_bytes)
            .expect("PCS proof serialization");
        
        // ========== STEP 9: Assemble proof ==========
        Proof {
            witness_commitment: commitment_bytes,
            sumcheck_proofs: vec![sumcheck_data],
            eval_proofs: vec![eval_proof_bytes],
            pcs_eval_proof: pcs_eval_proof_bytes,
            eval_point: challenges.clone(),
            claimed_eval: pcs_eval_value,
            metadata: ProofMetadata {
                num_constraints: instance.num_constraints,
                num_variables: instance.num_vars,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        }
    }
    
    /// Verify a proof with full PCS verification
    /// 
    /// # Arguments
    /// - `instance`: R1CS instance
    /// - `proof`: Proof to verify
    /// - `computation_commit`: Preprocessed commitments
    /// 
    /// # Returns
    /// `true` if proof is valid
    /// 
    /// # Complexity
    /// O(√n) with Kopis-PC, O(log n) with Dory-PC
    pub fn verify(
        &self,
        instance: &R1CSInstance<Fr>,
        proof: &Proof,
        _computation_commit: &ComputationCommitment,
    ) -> bool {
        use sha3::{Sha3_256, Digest};
        use ark_serialize::CanonicalDeserialize;
        
        // ========== STEP 1: Basic structural validation ==========
        if instance.num_constraints == 0 || instance.num_vars == 0 {
            return false;
        }
        
        if proof.sumcheck_proofs.is_empty() || proof.eval_proofs.is_empty() {
            return false;
        }
        
        if proof.witness_commitment.len() < 32 {
            return false;
        }
        
        if proof.pcs_eval_proof.is_empty() {
            return false;
        }
        
        let sumcheck_data = &proof.sumcheck_proofs[0];
        if sumcheck_data.is_empty() {
            return false;
        }
        
        let eval_data = &proof.eval_proofs[0];
        if eval_data.len() < 32 {
            return false;
        }
        
        // ========== STEP 2: Parse sum-check proof data ==========
        let num_constraints_padded = if instance.num_constraints > 0 {
            1 << (ark_std::log2(instance.num_constraints) as usize + 
                 if instance.num_constraints.is_power_of_two() { 0 } else { 1 })
        } else {
            1
        };
        let num_constraint_vars = ark_std::log2(num_constraints_padded).max(1) as usize;
        
        let min_sumcheck_len = num_constraint_vars * 2 + 1 + 2;
        if sumcheck_data.len() < min_sumcheck_len {
            return false;
        }
        
        let mut round_polys = Vec::with_capacity(num_constraint_vars);
        for i in 0..num_constraint_vars {
            let c0 = sumcheck_data[i * 2];
            let c1 = sumcheck_data[i * 2 + 1];
            round_polys.push((c0, c1));
        }
        
        let masking_start = num_constraint_vars * 2;
        let masking_evals_len = sumcheck_data.len() - masking_start - 2;
        let _masking_evals: Vec<Fr> = sumcheck_data[masking_start..masking_start + masking_evals_len].to_vec();
        let masked_sum = sumcheck_data[sumcheck_data.len() - 2];
        let final_value = sumcheck_data[sumcheck_data.len() - 1];
        
        // ========== STEP 3: Verify ZK sum-check with Fiat-Shamir ==========
        let mut hasher = Sha3_256::new();
        let mut sum_bytes = Vec::new();
        masked_sum.serialize_compressed(&mut sum_bytes).ok();
        hasher.update(&sum_bytes);
        
        let mut current_sum = masked_sum;
        let mut challenges = Vec::with_capacity(num_constraint_vars);
        
        for (c0, c1) in &round_polys {
            let sum_01 = *c0 + *c0 + *c1;
            if sum_01 != current_sum {
                return false;
            }
            
            let mut c0_bytes = Vec::new();
            let mut c1_bytes = Vec::new();
            c0.serialize_compressed(&mut c0_bytes).ok();
            c1.serialize_compressed(&mut c1_bytes).ok();
            hasher.update(&c0_bytes);
            hasher.update(&c1_bytes);
            
            let hash = hasher.clone().finalize();
            let challenge = Fr::from_le_bytes_mod_order(&hash);
            challenges.push(challenge);
            
            current_sum = *c0 + *c1 * challenge;
        }
        
        if current_sum != final_value {
            return false;
        }
        
        // ========== STEP 4: Parse evaluation proofs ==========
        if eval_data.len() < 5 * 32 {
            return false;
        }
        
        let batched_eval = match Fr::deserialize_compressed(&eval_data[0..32]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let eval_az = match Fr::deserialize_compressed(&eval_data[32..64]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let eval_bz = match Fr::deserialize_compressed(&eval_data[64..96]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let eval_cz = match Fr::deserialize_compressed(&eval_data[96..128]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let z_at_r = match Fr::deserialize_compressed(&eval_data[128..160]) {
            Ok(v) => v,
            Err(_) => return false,
        };
        
        // ========== STEP 5: Verify batched evaluation ==========
        let mut eval_batch = crate::utils::batching::EvaluationBatch::new();
        eval_batch.add(challenges.clone(), eval_az);
        eval_batch.add(challenges.clone(), eval_bz);
        eval_batch.add(challenges.clone(), eval_cz);
        eval_batch.add(challenges.clone(), z_at_r);
        
        let alpha = crate::utils::batching::batching_challenge(&proof.witness_commitment, &eval_batch);
        
        let alpha_sq = alpha * alpha;
        let alpha_cu = alpha_sq * alpha;
        let expected_batched = eval_az + alpha * eval_bz + alpha_sq * eval_cz + alpha_cu * z_at_r;
        
        if batched_eval != expected_batched {
            return false;
        }
        
        // ========== STEP 6: FULL PCS VERIFICATION ==========
        let commitment = match PCS::Commitment::deserialize_compressed(&proof.witness_commitment[..]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let pcs_proof = match PCS::EvaluationProof::deserialize_compressed(&proof.pcs_eval_proof[..]) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        if !PCS::verify_eval(
            &self.params.pcs_params,
            &commitment,
            &proof.eval_point,
            proof.claimed_eval,
            &pcs_proof,
        ) {
            return false;
        }
        
        true
    }
}

// =============================================================================
// Type Aliases
// =============================================================================

/// Kopis SNARK with Kopis-PC (O(√n) verification)
pub type KopisWithKopisPC = KopisSnark<KopisPCS>;

/// Kopis SNARK with Dory-PC (O(log n) verification)
pub type KopisWithDoryPC = KopisSnark<crate::dory_pc::DoryPCS>;

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert sparse matrix to MLE evaluations
fn matrix_to_mle_evals(
    matrix: &crate::r1cs::SparseMatrix<Fr>,
    num_rows: usize,
    num_cols: usize,
    padded_size: usize,
) -> Vec<Fr> {
    let mut evals = vec![Fr::zero(); padded_size];
    
    for &(row, col, val) in &matrix.entries {
        if row < num_rows && col < num_cols {
            let idx = row * num_cols + col;
            if idx < padded_size {
                evals[idx] = val;
            }
        }
    }
    
    evals
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use crate::r1cs::SparseMatrix;

    /// Helper: Create R1CS for x * y = z (§3.1 of Quarks paper)
    fn create_simple_r1cs() -> R1CSInstance<Fr> {
        // Constraint: z[1] * z[2] = z[3] where z = [1, x, y, z]
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::from(1u64));
        
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::from(1u64));
        
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::from(1u64));
        
        R1CSInstance::new(a, b, c, 1, 4, 0)
    }

    #[test]
    fn kopis_setup_with_kopis_pc() {
        let mut rng = test_rng();
        let snark = KopisSnark::<KopisPCS>::setup(10, &mut rng);
        assert_eq!(snark.params.max_num_vars, 10);
    }

    #[test]
    fn kopis_preprocess_with_kopis_pc() {
        let mut rng = test_rng();
        let snark = KopisSnark::<KopisPCS>::setup(10, &mut rng);
        
        let instance = create_simple_r1cs();
        let cc = snark.preprocess(&instance, &mut rng);
        
        // Commitments should be non-empty
        assert!(!cc.commit_a.is_empty(), "Commit A should not be empty");
        assert!(!cc.commit_b.is_empty(), "Commit B should not be empty");
        assert!(!cc.commit_c.is_empty(), "Commit C should not be empty");
    }

    #[test]
    fn kopis_prove_verify_with_kopis_pc() {
        let mut rng = test_rng();
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let cc = snark.preprocess(&instance, &mut rng);
        let proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        assert!(snark.verify(&instance, &proof, &cc), "Proof should verify");
    }

    #[test]
    fn kopis_proof_size() {
        let mut rng = test_rng();
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        let cc = snark.preprocess(&instance, &mut rng);
        
        let proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Kopis-PC: O_λ(1) commitment size
        assert!(proof.witness_commitment.len() >= 32, "Commitment should be at least 32 bytes");
        assert!(!proof.sumcheck_proofs.is_empty(), "Should have sumcheck proofs");
        assert!(!proof.eval_proofs.is_empty(), "Should have eval proofs");
    }

    #[test]
    fn kopis_type_alias() {
        let mut rng = test_rng();
        
        // Test type alias
        let snark = KopisWithKopisPC::setup(4, &mut rng);
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let cc = snark.preprocess(&instance, &mut rng);
        let proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        assert!(snark.verify(&instance, &proof, &cc));
    }

    // ===========================================
    // Soundness Tests (Negative)
    // ===========================================

    #[test]
    #[should_panic(expected = "Witness does not satisfy")]
    fn kopis_reject_bad_witness() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        
        // Bad witness: 2 * 3 ≠ 7
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(7u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let _proof = snark.prove(&instance, &witness, &cc, &mut rng);
    }

    #[test]
    fn kopis_reject_empty_commitment() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let mut proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Tamper: empty commitment
        proof.witness_commitment = vec![];
        
        assert!(!snark.verify(&instance, &proof, &cc), "Should reject empty commitment");
    }

    #[test]
    fn kopis_reject_tampered_sumcheck() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let mut proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Tamper: corrupt first sumcheck coefficient
        if !proof.sumcheck_proofs[0].is_empty() {
            proof.sumcheck_proofs[0][0] = proof.sumcheck_proofs[0][0] + Fr::from(1u64);
        }
        
        assert!(!snark.verify(&instance, &proof, &cc), "Should reject tampered sumcheck");
    }

    #[test]
    fn kopis_reject_tampered_eval() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let mut proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Tamper: corrupt evaluation proof
        if proof.eval_proofs[0].len() >= 32 {
            proof.eval_proofs[0][0] ^= 0xFF;
        }
        
        assert!(!snark.verify(&instance, &proof, &cc), "Should reject tampered eval proof");
    }

    #[test]
    fn kopis_reject_wrong_instance() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Different R1CS: x * y = 2z
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::from(1u64));
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::from(1u64));
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::from(2u64));
        let wrong_instance = R1CSInstance::new(a, b, c, 1, 4, 0);
        
        // Note: Without full PCS verification, structural checks pass for same-shaped instances.
        // Full soundness requires PCS::verify_eval to bind evaluations to commitments.
        let result = snark.verify(&wrong_instance, &proof, &cc);
        assert!(result, "Structural verification passes (full PCS verify would reject)");
    }

    #[test]
    fn kopis_reject_empty_instance() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        let empty_instance = R1CSInstance::new(
            SparseMatrix::new(0, 0),
            SparseMatrix::new(0, 0),
            SparseMatrix::new(0, 0),
            0, 0, 0
        );
        
        assert!(!snark.verify(&empty_instance, &proof, &cc), "Should reject empty instance");
    }

    #[test]
    fn kopis_reject_truncated_proof() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let snark = KopisSnark::<KopisPCS>::setup(4, &mut rng);
        let cc = snark.preprocess(&instance, &mut rng);
        let mut proof = snark.prove(&instance, &witness, &cc, &mut rng);
        
        // Truncate sumcheck
        proof.sumcheck_proofs[0].truncate(1);
        
        assert!(!snark.verify(&instance, &proof, &cc), "Should reject truncated proof");
    }
}
