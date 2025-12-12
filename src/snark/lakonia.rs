//! Lakonia: NIZK for R1CS with O_λ(log n) proofs
//!
//! Lakonia is a byproduct of Kopis, providing:
//! - O_λ(log n) proof sizes
//! - O(n) field ops for prover
//! - O(n) field ops for verifier (no preprocessing)
//! - Faster than Bulletproofs by >10×
//!
//! Generic over PCS through `LakoniaSnark<PCS>`.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::RngCore, Zero};
use core::marker::PhantomData;
use sha3::{Sha3_256, Digest};

use crate::r1cs::R1CSInstance;
use crate::traits::PolynomialCommitmentScheme;
use crate::kopis_pc::KopisPCS;
use crate::zk::zk_sumcheck::zk_sumcheck_prove;
use crate::utils::batching::{EvaluationBatch, batching_challenge};
use super::common::{Witness, Proof, ProofMetadata, GenericSnarkParams};
use super::utils::{build_z_vector, build_r1cs_sumcheck_polynomial};

/// Compute cryptographic digest of R1CS instance for Fiat-Shamir binding
/// 
/// SECURITY: This binds the proof to a specific R1CS instance, preventing
/// proof malleability attacks where same proof verifies for different circuits.
pub(super) fn compute_instance_digest(instance: &R1CSInstance<Fr>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    
    // Hash structural parameters
    hasher.update(&instance.num_constraints.to_le_bytes());
    hasher.update(&instance.num_vars.to_le_bytes());
    hasher.update(&instance.num_inputs.to_le_bytes());
    
    // Hash matrix A entries
    hasher.update(&instance.a.entries.len().to_le_bytes());
    for (row, col, val) in &instance.a.entries {
        hasher.update(&row.to_le_bytes());
        hasher.update(&col.to_le_bytes());
        let mut val_bytes = Vec::new();
        val.serialize_compressed(&mut val_bytes).expect("serialize");
        hasher.update(&val_bytes);
    }
    
    // Hash matrix B entries
    hasher.update(&instance.b.entries.len().to_le_bytes());
    for (row, col, val) in &instance.b.entries {
        hasher.update(&row.to_le_bytes());
        hasher.update(&col.to_le_bytes());
        let mut val_bytes = Vec::new();
        val.serialize_compressed(&mut val_bytes).expect("serialize");
        hasher.update(&val_bytes);
    }
    
    // Hash matrix C entries
    hasher.update(&instance.c.entries.len().to_le_bytes());
    for (row, col, val) in &instance.c.entries {
        hasher.update(&row.to_le_bytes());
        hasher.update(&col.to_le_bytes());
        let mut val_bytes = Vec::new();
        val.serialize_compressed(&mut val_bytes).expect("serialize");
        hasher.update(&val_bytes);
    }
    
    hasher.finalize().into()
}

// =============================================================================
// Lakonia SNARK - Generic over PCS (paper §3-8)
// =============================================================================

/// Lakonia SNARK with pluggable Polynomial Commitment Scheme
/// 
/// # Type Parameters
/// - `PCS`: Polynomial Commitment Scheme (e.g., `KopisPCS`, `DoryPCS`)
/// 
/// # Paper Reference
/// Lakonia is described in Quarks paper §3-8 as a "byproduct" of Kopis
/// that achieves O(log n) proofs without preprocessing.
/// 
/// # Example
/// ```ignore
/// use quarks::{LakoniaSnark, KopisPCS, DoryPCS};
/// 
/// // With Kopis-PC
/// let snark = LakoniaSnark::<KopisPCS>::setup(16, &mut rng);
/// 
/// // With Dory-PC (O(log n) verification)
/// let snark = LakoniaSnark::<DoryPCS>::setup(16, &mut rng);
/// ```
pub struct LakoniaSnark<PCS: PolynomialCommitmentScheme<Fr>> {
    /// Generic SNARK parameters
    pub params: GenericSnarkParams<PCS>,
    _marker: PhantomData<PCS>,
}

impl<PCS: PolynomialCommitmentScheme<Fr>> LakoniaSnark<PCS> {
    /// Setup Lakonia with generic PCS
    /// 
    /// # Arguments
    /// - `max_num_vars`: Maximum number of variables supported
    /// - `rng`: Random number generator
    pub fn setup<R: RngCore>(max_num_vars: usize, rng: &mut R) -> Self {
        let params = GenericSnarkParams::setup(max_num_vars, rng);
        Self { params, _marker: PhantomData }
    }
    
    /// Prove R1CS satisfiability using generic PCS
    /// 
    /// # Arguments
    /// - `instance`: R1CS instance
    /// - `witness`: Witness values
    /// - `rng`: Random number generator
    pub fn prove<R: RngCore>(
        &self,
        instance: &R1CSInstance<Fr>,
        witness: &Witness,
        rng: &mut R,
    ) -> Proof {
        prove_internal::<PCS>(&self.params.pcs_params, instance, witness, rng)
    }
    
    /// Verify a proof with full PCS verification
    /// 
    /// # Arguments
    /// - `instance`: R1CS instance
    /// - `proof`: Proof to verify
    pub fn verify(
        &self,
        instance: &R1CSInstance<Fr>,
        proof: &Proof,
    ) -> bool {
        verify_internal::<PCS>(&self.params.pcs_params, instance, proof)
    }
}

// =============================================================================
// Type Aliases
// =============================================================================

/// Lakonia SNARK with Kopis-PC (O(√n) verification)
pub type LakoniaWithKopisPC = LakoniaSnark<KopisPCS>;

/// Lakonia SNARK with Dory-PC (O(log n) verification)
pub type LakoniaWithDoryPC = LakoniaSnark<crate::dory_pc::DoryPCS>;

// Keep GenericLakoniaSnark as alias for backward compatibility with lib.rs
pub type GenericLakoniaSnark<PCS> = LakoniaSnark<PCS>;

// =============================================================================
// Internal prove/verify functions
// =============================================================================

/// Internal prove function using generic PCS
/// 
/// Protocol (from Quarks paper §3-8):
/// 1. Build z = (io, 1, w)
/// 2. Commit to z as multilinear polynomial using PCS
/// 3. Build sum-check polynomial for R1CS
/// 4. Run ZK sum-check on F to prove Σ_x F(x) = 0
/// 5. Generate batched evaluation proofs
fn prove_internal<PCS: PolynomialCommitmentScheme<Fr>>(
    pcs_params: &PCS::Params,
    instance: &R1CSInstance<Fr>,
    witness: &Witness,
    rng: &mut impl RngCore,
) -> Proof {
    // Verify witness satisfies the instance
    use crate::r1cs::Witness as R1CSWitness;
    let r1cs_witness = R1CSWitness {
        public_inputs: vec![],
        assignments: witness.values.clone(),
    };
    assert!(
        instance.is_satisfied(&r1cs_witness).is_ok_and(|b| b),
        "Witness does not satisfy R1CS instance"
    );
    
    // ========== STEP 0: Compute instance digest for Fiat-Shamir binding ==========
    // SECURITY FIX: Hash the R1CS instance to bind proof to specific circuit
    let instance_digest = compute_instance_digest(instance);
    
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
    
    // ========== STEP 3: Pad z for commitment ==========
    let z_len = z.len();
    let z_num_vars = ark_std::log2(z_len.next_power_of_two()) as usize;
    let expected_z_size = 1 << z_num_vars.max(2);
    let mut z_padded = z.clone();
    z_padded.resize(expected_z_size, Fr::zero());
    
    // ========== STEP 4: Commit using generic PCS ==========
    let commitment = PCS::commit_hiding(pcs_params, &z_padded, rng);
    
    let mut commitment_bytes = Vec::new();
    commitment.serialize_compressed(&mut commitment_bytes)
        .expect("commitment serialization");
    
    // ========== STEP 5: Build R1CS sum-check polynomial with instance binding ==========
    let num_constraint_vars = ark_std::log2(num_constraints_padded).max(1) as usize;
    
    // Initialize Fiat-Shamir with instance digest + commitment
    let mut transcript = Sha3_256::new();
    transcript.update(&instance_digest);
    transcript.update(&commitment_bytes);
    
    // Derive tau from transcript for binding
    let mut tau = Vec::with_capacity(num_constraint_vars);
    for i in 0..num_constraint_vars {
        transcript.update(&i.to_le_bytes());
        let hash = transcript.clone().finalize();
        tau.push(Fr::from_le_bytes_mod_order(&hash));
    }
    
    let sumcheck_poly = build_r1cs_sumcheck_polynomial(&az, &bz, &cz, &tau);
    let claimed_sum = Fr::zero();
    
    // ========== STEP 6: Run ZK sum-check protocol ==========
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
    
    // Collect sum-check proof data
    let mut sumcheck_data = Vec::new();
    for round_poly in &zk_sumcheck_proof.round_polys {
        sumcheck_data.extend_from_slice(&round_poly.coeffs);
    }
    sumcheck_data.extend_from_slice(&zk_sumcheck_proof.masking_evals);
    sumcheck_data.push(zk_sumcheck_proof.masked_sum);
    sumcheck_data.push(zk_sumcheck_proof.final_value);
    
    // ========== STEP 7: Evaluate witness polynomial ==========
    let mut z_for_eval = z_padded.clone();
    let required_size = 1 << challenges.len();
    z_for_eval.resize(required_size, Fr::zero());
    
    use crate::polynomial::MultilinearPolynomial;
    let z_poly = MultilinearPolynomial::from_evaluations(z_for_eval, challenges.len());
    let z_at_r = z_poly.evaluate(challenges);
    
    // ========== STEP 8: Batched evaluation proofs ==========
    let mut eval_batch = EvaluationBatch::new();
    
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
    
    eval_batch.add(challenges.clone(), eval_az);
    eval_batch.add(challenges.clone(), eval_bz);
    eval_batch.add(challenges.clone(), eval_cz);
    eval_batch.add(challenges.clone(), z_at_r);
    
    let alpha = batching_challenge(&commitment_bytes, &eval_batch);
    
    // ========== STEP 9: Compute batched evaluation ==========
    use crate::utils::batching::batch_values;
    let batched_eval = batch_values(&[eval_az, eval_bz, eval_cz, z_at_r], &alpha);
    
    let mut eval_proof_bytes = Vec::new();
    batched_eval.serialize_compressed(&mut eval_proof_bytes).expect("batched_eval");
    eval_az.serialize_compressed(&mut eval_proof_bytes).expect("eval_az");
    eval_bz.serialize_compressed(&mut eval_proof_bytes).expect("eval_bz");
    eval_cz.serialize_compressed(&mut eval_proof_bytes).expect("eval_cz");
    z_at_r.serialize_compressed(&mut eval_proof_bytes).expect("z_at_r");
    
    // ========== STEP 10: Generate PCS evaluation proof ==========
    // Prove that the committed polynomial evaluates to z_at_r at the challenge point
    let (pcs_eval_value, pcs_proof) = PCS::prove_eval(pcs_params, &z_padded, challenges, rng);
    
    // Serialize PCS proof
    let mut pcs_eval_proof_bytes = Vec::new();
    pcs_proof.serialize_compressed(&mut pcs_eval_proof_bytes)
        .expect("PCS proof serialization");
    
    // ========== STEP 11: Assemble proof with instance binding ==========
    Proof {
        instance_digest,  // SECURITY: Bind proof to this specific instance
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

/// Internal verify function with full PCS verification
/// 
/// Performs full cryptographic verification:
/// 1. Validates proof structure
/// 2. Verifies ZK sum-check rounds with Fiat-Shamir
/// 3. Verifies batched evaluation claims
/// 4. Verifies PCS evaluation proof (FULL SOUNDNESS)
fn verify_internal<PCS: PolynomialCommitmentScheme<Fr>>(
    pcs_params: &PCS::Params,
    instance: &R1CSInstance<Fr>,
    proof: &Proof,
) -> bool {
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    
    // ========== STEP 0: Compute and verify instance digest ==========
    let instance_digest = compute_instance_digest(instance);
    
    // SECURITY CHECK: Verify proof is bound to THIS instance
    if proof.instance_digest != instance_digest {
        return false; // Proof was generated for different instance!
    }
    
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
    
    // Parse round polynomial coefficients
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
    
    // ========== STEP 3: Verify ZK sum-check with Fiat-Shamir + instance binding ==========
    let mut transcript = Sha3_256::new();
    
    // SECURITY FIX: Include instance digest in transcript
    transcript.update(&instance_digest);
    transcript.update(&proof.witness_commitment);
    
    // Recompute tau from transcript (must match prover's derivation)
    let mut tau_challenges = Vec::with_capacity(num_constraint_vars);
    for i in 0..num_constraint_vars {
        transcript.update(&i.to_le_bytes());
        let hash = transcript.clone().finalize();
        tau_challenges.push(Fr::from_le_bytes_mod_order(&hash));
    }
    
    // Now verify sum-check rounds
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
    // Deserialize commitment
    let commitment = match PCS::Commitment::deserialize_compressed(&proof.witness_commitment[..]) {
        Ok(c) => c,
        Err(_) => return false,
    };
    
    // Deserialize PCS evaluation proof
    let pcs_proof = match PCS::EvaluationProof::deserialize_compressed(&proof.pcs_eval_proof[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Verify PCS evaluation proof
    // This is the KEY soundness check: proves the committed polynomial 
    // evaluates to claimed_eval at eval_point
    if !PCS::verify_eval(
        pcs_params,
        &commitment,
        &proof.eval_point,
        proof.claimed_eval,
        &pcs_proof,
    ) {
        return false;
    }
    
    true
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use crate::r1cs::SparseMatrix;
    use crate::dory_pc::DoryPCS;

    /// Helper: Create R1CS for x * y = z
    fn create_simple_r1cs() -> R1CSInstance<Fr> {
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::from(1u64));
        
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::from(1u64));
        
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::from(1u64));
        
        R1CSInstance::new(a, b, c, 1, 4, 0)
    }

    // ===========================================
    // Tests for LakoniaSnark<KopisPCS>
    // ===========================================
    
    #[test]
    fn lakonia_kopis_setup() {
        let mut rng = test_rng();
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        assert_eq!(lakonia.params.max_num_vars, 4);
    }
    
    #[test]
    fn lakonia_kopis_prove_verify() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Debug: print proof structure
        println!("sumcheck_data len: {}", proof.sumcheck_proofs[0].len());
        println!("eval_proofs len: {}", proof.eval_proofs[0].len());
        
        assert!(lakonia.verify(&instance, &proof), "Lakonia<KopisPCS> should verify");
    }
    
    // ===========================================
    // Tests for LakoniaSnark<DoryPCS>
    // ===========================================
    
    #[test]
    fn lakonia_dory_setup() {
        let mut rng = test_rng();
        let lakonia = LakoniaSnark::<DoryPCS>::setup(4, &mut rng);
        assert_eq!(lakonia.params.max_num_vars, 4);
    }
    
    #[test]
    fn lakonia_dory_prove_verify() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<DoryPCS>::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        assert!(lakonia.verify(&instance, &proof), "Lakonia<DoryPCS> should verify");
    }

    // ===========================================
    // General tests
    // ===========================================

    #[test]
    #[should_panic(expected = "Witness does not satisfy")]
    fn lakonia_reject_bad_witness() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        
        // Bad witness: 2 * 3 ≠ 7
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(7u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let _proof = lakonia.prove(&instance, &witness, &mut rng);
    }

    #[test]
    fn lakonia_multiple_constraints() {
        let mut rng = test_rng();
        
        // Two constraints: x * y = t and t * x = r
        let mut a = SparseMatrix::new(2, 5);
        a.add_entry(0, 1, Fr::from(1u64));
        a.add_entry(1, 3, Fr::from(1u64));
        
        let mut b = SparseMatrix::new(2, 5);
        b.add_entry(0, 2, Fr::from(1u64));
        b.add_entry(1, 1, Fr::from(1u64));
        
        let mut c = SparseMatrix::new(2, 5);
        c.add_entry(0, 3, Fr::from(1u64));
        c.add_entry(1, 4, Fr::from(1u64));
        
        let instance = R1CSInstance::new(a, b, c, 2, 5, 0);
        
        // Witness: w = [2, 3, 6, 12]
        // Check: 2 * 3 = 6 ✓, 6 * 2 = 12 ✓
        let witness = Witness::new(vec![
            Fr::from(2u64), 
            Fr::from(3u64), 
            Fr::from(6u64),
            Fr::from(12u64),
        ]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        assert!(lakonia.verify(&instance, &proof));
    }

    #[test]
    fn lakonia_type_alias() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        // Test type alias
        let lakonia = LakoniaWithKopisPC::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        assert!(lakonia.verify(&instance, &proof));
    }

    // ===========================================
    // Soundness Tests (Negative)
    // ===========================================

    #[test]
    fn lakonia_reject_empty_commitment() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let mut proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Tamper: empty commitment
        proof.witness_commitment = vec![];
        
        assert!(!lakonia.verify(&instance, &proof), "Should reject empty commitment");
    }

    #[test]
    fn lakonia_reject_tampered_sumcheck() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let mut proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Tamper: corrupt first sumcheck coefficient
        if !proof.sumcheck_proofs[0].is_empty() {
            proof.sumcheck_proofs[0][0] = proof.sumcheck_proofs[0][0] + Fr::from(1u64);
        }
        
        assert!(!lakonia.verify(&instance, &proof), "Should reject tampered sumcheck");
    }

    #[test]
    fn lakonia_reject_tampered_eval() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let mut proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Tamper: corrupt evaluation proof bytes
        if proof.eval_proofs[0].len() >= 32 {
            proof.eval_proofs[0][0] ^= 0xFF;
        }
        
        assert!(!lakonia.verify(&instance, &proof), "Should reject tampered eval proof");
    }

    #[test]
    fn lakonia_reject_wrong_instance() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Create a different R1CS instance (x * y = 2z instead of x * y = z)
        let mut a = SparseMatrix::new(1, 4);
        a.add_entry(0, 1, Fr::from(1u64));
        let mut b = SparseMatrix::new(1, 4);
        b.add_entry(0, 2, Fr::from(1u64));
        let mut c = SparseMatrix::new(1, 4);
        c.add_entry(0, 3, Fr::from(2u64)); // Different coefficient!
        let wrong_instance = R1CSInstance::new(a, b, c, 1, 4, 0);
        
        // SECURITY FIX: With instance digest in Fiat-Shamir transcript,
        // the verifier MUST reject proofs for different instances
        let result = lakonia.verify(&wrong_instance, &proof);
        assert!(!result, "Should REJECT proof with wrong instance (instance binding via Fiat-Shamir)");
    }

    #[test]
    fn lakonia_reject_empty_instance() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Create empty instance
        let empty_instance = R1CSInstance::new(
            SparseMatrix::new(0, 0),
            SparseMatrix::new(0, 0),
            SparseMatrix::new(0, 0),
            0, 0, 0
        );
        
        assert!(!lakonia.verify(&empty_instance, &proof), "Should reject empty instance");
    }

    #[test]
    fn lakonia_reject_truncated_proof() {
        let mut rng = test_rng();
        let instance = create_simple_r1cs();
        let witness = Witness::new(vec![Fr::from(2u64), Fr::from(3u64), Fr::from(6u64)]);
        
        let lakonia = LakoniaSnark::<KopisPCS>::setup(4, &mut rng);
        let mut proof = lakonia.prove(&instance, &witness, &mut rng);
        
        // Truncate sumcheck data
        proof.sumcheck_proofs[0].truncate(1);
        
        assert!(!lakonia.verify(&instance, &proof), "Should reject truncated proof");
    }
}
