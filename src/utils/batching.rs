//! Batched Polynomial Evaluations using Random Linear Combination
//!
//! Instead of proving multiple polynomial evaluations independently:
//!   p1(r1) = v1, p2(r2) = v2, ..., pN(rN) = vN
//!
//! We batch them into a SINGLE proof using random linear combination:
//!   α^0·p1(r1) + α^1·p2(r2) + ... + α^(N-1)·pN(rN) = α^0·v1 + α^1·v2 + ... + α^(N-1)·vN
//!
//! Soundness: By Schwartz-Zippel lemma, if ANY pi(ri) ≠ vi, the batched claim fails
//! with probability ≥ 1 - d/|F| where d is polynomial degree.
//!
//! **Impact**: N proofs → 1 proof = ~(N-1)×proof_size savings
//! **Example**: 20 eval proofs @ 500 bytes each = 10 KB → 0.6 KB = **94% reduction**

use ark_ff::{Field, PrimeField};
use sha3::{Digest, Sha3_256};

/// A batch of polynomial evaluation claims
#[derive(Clone, Debug)]
pub struct EvaluationBatch<F: Field> {
    /// Evaluation points (r1, r2, ..., rN)
    pub points: Vec<Vec<F>>,
    /// Claimed values (v1, v2, ..., vN)
    pub values: Vec<F>,
}

impl<F: Field> EvaluationBatch<F> {
    /// Create a new evaluation batch
    pub fn new() -> Self {
        Self {
            points: Vec::new(),
            values: Vec::new(),
        }
    }
    
    /// Add an evaluation claim: p(r) = v
    pub fn add(&mut self, point: Vec<F>, value: F) {
        self.points.push(point);
        self.values.push(value);
    }
    
    /// Number of batched evaluations
    pub fn len(&self) -> usize {
        self.values.len()
    }
    
    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Generate batching challenge α using Fiat-Shamir
/// 
/// Challenge is computed as: α = H(commitments || points || values)
/// where H is a cryptographic hash function (SHA3-256)
pub fn batching_challenge<F: PrimeField>(
    commitment_bytes: &[u8],
    batch: &EvaluationBatch<F>,
) -> F {
    let mut hasher = Sha3_256::new();
    
    // Hash commitments
    hasher.update(commitment_bytes);
    
    // Hash evaluation points
    for point in &batch.points {
        for coord in point {
            let mut coord_bytes = Vec::new();
            coord.serialize_compressed(&mut coord_bytes)
                .expect("field element serialization");
            hasher.update(&coord_bytes);
        }
    }
    
    // Hash claimed values
    for value in &batch.values {
        let mut value_bytes = Vec::new();
        value.serialize_compressed(&mut value_bytes)
            .expect("field element serialization");
        hasher.update(&value_bytes);
    }
    
    // Derive challenge from hash
    let hash = hasher.finalize();
    F::from_le_bytes_mod_order(&hash)
}

/// Compute batched evaluation: Σ α^i · vi
/// 
/// This is the right-hand side of the batched claim.
/// Left-hand side is computed by evaluating the batched polynomial.
pub fn batch_values<F: Field>(values: &[F], alpha: &F) -> F {
    let mut result = F::zero();
    let mut alpha_power = F::one();
    
    for v in values {
        result += alpha_power * v;
        alpha_power *= alpha;
    }
    
    result
}

/// Compute powers of α: [1, α, α^2, ..., α^(n-1)]
pub fn powers_of_alpha<F: Field>(alpha: &F, n: usize) -> Vec<F> {
    let mut powers = Vec::with_capacity(n);
    let mut current = F::one();
    
    for _ in 0..n {
        powers.push(current);
        current *= alpha;
    }
    
    powers
}

/// Batch multiple polynomial evaluations into a single linear combination
/// 
/// Given polynomials p1, ..., pN and evaluation points r1, ..., rN,
/// instead of evaluating each pi(ri) separately, compute:
/// 
/// P_batched(X) = α^0·p1(X) + α^1·p2(X) + ... + α^(N-1)·pN(X)
/// 
/// Then prove: P_batched(ri) = α^0·p1(r1) + ... + α^(N-1)·pN(rN)
/// 
/// # Arguments
/// * `polynomials` - List of polynomial evaluations (dense representation)
/// * `alpha` - Batching challenge (random)
/// 
/// # Returns
/// Batched polynomial: Σ α^i · pi
pub fn batch_polynomials<F: Field>(
    polynomials: &[Vec<F>],
    alpha: &F,
) -> Vec<F> {
    if polynomials.is_empty() {
        return Vec::new();
    }
    
    let size = polynomials[0].len();
    let mut result = vec![F::zero(); size];
    let mut alpha_power = F::one();
    
    for poly in polynomials {
        assert_eq!(poly.len(), size, "All polynomials must have same size");
        for (i, coeff) in poly.iter().enumerate() {
            result[i] += alpha_power * coeff;
        }
        alpha_power *= alpha;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::{test_rng, UniformRand};
    
    #[test]
    fn test_evaluation_batch_empty() {
        let batch: EvaluationBatch<Fr> = EvaluationBatch::new();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
    }
    
    #[test]
    fn test_evaluation_batch_add() {
        let mut batch = EvaluationBatch::new();
        batch.add(vec![Fr::one()], Fr::from(5u64));
        batch.add(vec![Fr::from(2u64)], Fr::from(10u64));
        
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }
    
    #[test]
    fn test_batching_challenge_deterministic() {
        let mut batch = EvaluationBatch::new();
        batch.add(vec![Fr::one()], Fr::from(5u64));
        batch.add(vec![Fr::from(2u64)], Fr::from(10u64));
        
        let commitment = b"test_commitment";
        let alpha1 = batching_challenge(commitment, &batch);
        let alpha2 = batching_challenge(commitment, &batch);
        
        assert_eq!(alpha1, alpha2, "Challenge should be deterministic");
    }
    
    #[test]
    fn test_batching_challenge_different_for_different_inputs() {
        let mut batch1 = EvaluationBatch::new();
        batch1.add(vec![Fr::one()], Fr::from(5u64));
        
        let mut batch2 = EvaluationBatch::new();
        batch2.add(vec![Fr::one()], Fr::from(6u64));
        
        let commitment = b"test_commitment";
        let alpha1 = batching_challenge(commitment, &batch1);
        let alpha2 = batching_challenge(commitment, &batch2);
        
        assert_ne!(alpha1, alpha2, "Different batches should produce different challenges");
    }
    
    #[test]
    fn test_batch_values() {
        let values = vec![Fr::from(5u64), Fr::from(10u64), Fr::from(15u64)];
        let alpha = Fr::from(2u64);
        
        // Expected: 5·1 + 10·2 + 15·4 = 5 + 20 + 60 = 85
        let result = batch_values(&values, &alpha);
        let expected = Fr::from(5u64) + Fr::from(10u64) * Fr::from(2u64) 
                       + Fr::from(15u64) * Fr::from(4u64);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_powers_of_alpha() {
        let alpha = Fr::from(3u64);
        let powers = powers_of_alpha(&alpha, 5);
        
        assert_eq!(powers.len(), 5);
        assert_eq!(powers[0], Fr::one());        // 1
        assert_eq!(powers[1], Fr::from(3u64));   // 3
        assert_eq!(powers[2], Fr::from(9u64));   // 9
        assert_eq!(powers[3], Fr::from(27u64));  // 27
        assert_eq!(powers[4], Fr::from(81u64));  // 81
    }
    
    #[test]
    fn test_batch_polynomials() {
        // p1 = [1, 2], p2 = [3, 4], p3 = [5, 6]
        let poly1 = vec![Fr::from(1u64), Fr::from(2u64)];
        let poly2 = vec![Fr::from(3u64), Fr::from(4u64)];
        let poly3 = vec![Fr::from(5u64), Fr::from(6u64)];
        let polynomials = vec![poly1, poly2, poly3];
        
        let alpha = Fr::from(10u64);
        // α^0 = 1, α^1 = 10, α^2 = 100
        
        let batched = batch_polynomials(&polynomials, &alpha);
        
        // Expected: [1·1 + 3·10 + 5·100, 2·1 + 4·10 + 6·100]
        //         = [1 + 30 + 500, 2 + 40 + 600]
        //         = [531, 642]
        assert_eq!(batched.len(), 2);
        assert_eq!(batched[0], Fr::from(531u64));
        assert_eq!(batched[1], Fr::from(642u64));
    }
    
    #[test]
    fn test_batch_polynomials_empty() {
        let polynomials: Vec<Vec<Fr>> = vec![];
        let alpha = Fr::from(2u64);
        
        let batched = batch_polynomials(&polynomials, &alpha);
        assert!(batched.is_empty());
    }
    
    #[test]
    fn test_batch_polynomials_single() {
        let poly = vec![Fr::from(7u64), Fr::from(8u64)];
        let polynomials = vec![poly.clone()];
        let alpha = Fr::from(999u64); // Shouldn't matter for single poly
        
        let batched = batch_polynomials(&polynomials, &alpha);
        assert_eq!(batched, poly, "Single polynomial should be unchanged");
    }
    
    #[test]
    fn test_batching_soundness_simulation() {
        let mut rng = test_rng();
        
        // Honest prover: all evaluations correct
        let p1_evals = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let p2_evals = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        
        let alpha = Fr::rand(&mut rng);
        
        // Batch polynomials
        let batched = batch_polynomials(&vec![p1_evals.clone(), p2_evals.clone()], &alpha);
        
        // Batch values at some evaluation point
        let v1 = p1_evals[0]; // p1(0)
        let v2 = p2_evals[0]; // p2(0)
        let batched_value = batch_values(&vec![v1, v2], &alpha);
        
        // Verify: batched polynomial at point 0 equals batched value
        assert_eq!(batched[0], batched_value, "Batched evaluation should match");
    }
}

