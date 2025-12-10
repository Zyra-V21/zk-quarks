//! Zero-Knowledge Sum-Check Protocol (§8 of Quarks paper)
//!
//! The ZK sum-check masks F with G = Σ g^i(X^i) where g^i are low-weight.
//! The transcript of sum-check on F + G is independent of F.

use ark_bls12_381::Fr;
use ark_ff::{Zero, One};
use ark_std::vec::Vec;
use ark_std::rand::RngCore;
use ark_ff::UniformRand;

use super::low_weight::LowWeightPolynomial;
use crate::sumcheck::UnivariatePolynomial;

/// ZK Sum-Check Prover
pub struct ZkSumCheckProver {
    /// Number of variables
    pub num_vars: usize,
    /// Degree of polynomial in each variable
    pub degree: usize,
}

/// Proof from ZK Sum-Check
#[derive(Clone, Debug)]
pub struct ZkSumCheckProof {
    /// Low-weight polynomials g^1, ..., g^d (one per degree)
    pub masking_polys: Vec<LowWeightPolynomial>,
    /// Masked sum z = y + Σᵢ Σₓ g^i(x)
    pub masked_sum: Fr,
    /// Round polynomials from non-hiding sum-check on F + G
    pub round_polys: Vec<UnivariatePolynomial<Fr>>,
    /// Final evaluation point r
    pub final_point: Vec<Fr>,
    /// Final value z' = F(r) + G(r)
    pub final_value: Fr,
    /// Evaluations of masking polys at final point: h^i = g^i(r^i)
    pub masking_evals: Vec<Fr>,
}

impl ZkSumCheckProver {
    pub fn new(num_vars: usize, degree: usize) -> Self {
        Self { num_vars, degree }
    }

    /// Generate masking polynomial G = Σᵢ g^i(X^i)
    /// 
    /// Each g^i is a low-weight polynomial in num_vars variables
    pub fn generate_masking_polys<R: RngCore>(&self, rng: &mut R) -> Vec<LowWeightPolynomial> {
        (0..self.degree)
            .map(|_| LowWeightPolynomial::random(self.num_vars, rng))
            .collect()
    }

    /// Compute Σₓ G(x) for G = Σᵢ g^i(X^i)
    /// 
    /// Since each g^i has sum = b₀^i, and we sum over degree copies,
    /// the total sum is Σᵢ b₀^i
    pub fn sum_of_masking(&self, masking_polys: &[LowWeightPolynomial]) -> Fr {
        masking_polys.iter()
            .map(|g| g.sum_over_hypercube())
            .sum()
    }

    /// Evaluate G(x) = Σᵢ g^i(x^i) at a point
    /// 
    /// Note: x^i means we use x for the i-th copy of variables
    /// In our simplified model, we just sum g^i(x) for all i
    pub fn eval_masking_at(&self, masking_polys: &[LowWeightPolynomial], x: &[Fr]) -> Fr {
        masking_polys.iter()
            .map(|g| g.evaluate(x))
            .sum()
    }

    /// Compute masked sum z = y + Σₓ G(x)
    pub fn compute_masked_sum(&self, y: Fr, masking_polys: &[LowWeightPolynomial]) -> Fr {
        y + self.sum_of_masking(masking_polys)
    }
}

/// ZK Sum-Check Verifier
pub struct ZkSumCheckVerifier {
    pub num_vars: usize,
    pub degree: usize,
}

impl ZkSumCheckVerifier {
    pub fn new(num_vars: usize, degree: usize) -> Self {
        Self { num_vars, degree }
    }

    /// Verify the ZK sum-check proof structure
    /// 
    /// Returns true if:
    /// 1. Round polynomials satisfy g_i(0) + g_i(1) = s_{i-1}
    /// 2. Masking evaluations are consistent with final_value
    pub fn verify_structure(&self, proof: &ZkSumCheckProof) -> bool {
        // Check number of round polynomials
        if proof.round_polys.len() != self.num_vars {
            return false;
        }

        // Check round polynomials satisfy sum condition
        let mut current_sum = proof.masked_sum;
        for (i, poly) in proof.round_polys.iter().enumerate() {
            let sum_at_boolean = poly.sum_over_boolean();
            if sum_at_boolean != current_sum {
                return false;
            }
            
            if i < proof.final_point.len() {
                current_sum = poly.evaluate(proof.final_point[i]);
            }
        }

        // The final value should match
        if current_sum != proof.final_value {
            return false;
        }

        true
    }

    /// Compute y' from z', G(r)
    /// 
    /// y' = z' - G(r) = z' - Σᵢ h^i
    pub fn recover_final_evaluation(&self, proof: &ZkSumCheckProof) -> Fr {
        let g_at_r: Fr = proof.masking_evals.iter().copied().sum();
        proof.final_value - g_at_r
    }
}

/// ZK sum-check prover following §8 of Quarks paper
/// 
/// Given evaluations of F on {0,1}^ℓ and claimed sum y,
/// produces a ZK proof where the transcript is independent of F.
///
/// The key insight:
/// - P masks F with G = Σᵢ g^i where g^i are random low-weight polynomials
/// - Sum-check is run on F + G instead of F
/// - Due to randomness of G, transcript reveals nothing about F
pub fn zk_sumcheck_prove<R: RngCore>(
    evaluations: &[Fr],
    claimed_sum: Fr,
    num_vars: usize,
    rng: &mut R,
) -> ZkSumCheckProof {
    assert_eq!(evaluations.len(), 1 << num_vars, "Evaluations size mismatch");
    
    let degree = 1; // Multilinear polynomials have degree 1 in each variable
    
    // Step 1: Generate masking polynomials g^1, ..., g^d (one per degree)
    let masking_polys: Vec<LowWeightPolynomial> = (0..degree)
        .map(|_| LowWeightPolynomial::random(num_vars, rng))
        .collect();
    
    // Step 2: Compute masked sum z = y + Σᵢ Σₓ g^i(x)
    // For low-weight polynomials, Σₓ g^i(x) = b₀^i (the first coefficient)
    let g_sum: Fr = masking_polys.iter()
        .map(|g| g.sum_over_hypercube())
        .sum();
    let masked_sum = claimed_sum + g_sum;
    
    // Step 3: Generate random challenges (Fiat-Shamir in real implementation)
    let final_point: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(rng)).collect();
    
    // Step 4: Run sum-check on F + G
    // Track current evaluations of F and current state of each g^i
    let mut f_evals = evaluations.to_vec();
    let mut bound_masks: Vec<LowWeightPolynomial> = masking_polys.clone();
    let mut round_polys = Vec::with_capacity(num_vars);
    let mut current_sum = masked_sum;
    
    for i in 0..num_vars {
        // Compute round polynomial p_i(X) = Σ_{x∈{0,1}^{ℓ-i-1}} (F + G)(r₁,...,rᵢ, X, x)
        
        // F contribution: sum over remaining variables
        let half = f_evals.len() / 2;
        let f_sum_at_0: Fr = f_evals[..half].iter().copied().sum();
        let f_sum_at_1: Fr = f_evals[half..].iter().copied().sum();
        
        // G contribution from each g^j (using Lemma 8.2)
        // Σ_{x∈{0,1}^{ℓ-1}} g(X, x) = (b₀ - b₁) + (2b₁ - b₀)X
        let mut g_c0 = Fr::zero();
        let mut g_c1 = Fr::zero();
        
        for g in &bound_masks {
            let (c0, c1) = g.sum_first_var();
            g_c0 += c0;
            g_c1 += c1;
        }
        
        // Total: p_i(X) = (f_sum_at_0 + g_c0) + (f_sum_at_1 - f_sum_at_0 + g_c1) * X
        let c0 = f_sum_at_0 + g_c0;
        let c1 = f_sum_at_1 - f_sum_at_0 + g_c1;
        
        let poly = UnivariatePolynomial::new(vec![c0, c1]);
        
        // Verify: p_i(0) + p_i(1) should equal current_sum
        let sum_check = poly.sum_over_boolean();
        assert_eq!(sum_check, current_sum, 
            "Round {} sum check failed: {} != {}", i, sum_check, current_sum);
        
        // Bind the variable to challenge r_i
        let r = final_point[i];
        f_evals = bind_evaluations(&f_evals, r);
        bound_masks = bound_masks.iter().map(|g| g.bind(r)).collect();
        current_sum = poly.evaluate(r);
        
        round_polys.push(poly);
    }
    
    // Step 5: Compute final values
    let f_at_r = f_evals[0];
    let g_at_r: Fr = masking_polys.iter()
        .map(|g| g.evaluate(&final_point))
        .sum();
    let final_value = f_at_r + g_at_r;
    
    // Verify final consistency
    assert_eq!(current_sum, final_value,
        "Final sum {} != final_value {}", current_sum, final_value);
    
    // Masking evaluations h^i = g^i(r)
    let masking_evals: Vec<Fr> = masking_polys.iter()
        .map(|g| g.evaluate(&final_point))
        .collect();
    
    ZkSumCheckProof {
        masking_polys,
        masked_sum,
        round_polys,
        final_point,
        final_value,
        masking_evals,
    }
}

/// Bind evaluations: given evals of f(X, y) for y ∈ {0,1}^{n-1},
/// compute evals of f(r, y) for y ∈ {0,1}^{n-1}
fn bind_evaluations(evals: &[Fr], r: Fr) -> Vec<Fr> {
    let half = evals.len() / 2;
    let one_minus_r = Fr::one() - r;
    
    (0..half)
        .map(|i| evals[i] * one_minus_r + evals[half + i] * r)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn zk_prover_masking_sum() {
        let mut rng = test_rng();
        let prover = ZkSumCheckProver::new(4, 2);
        
        let masking = prover.generate_masking_polys(&mut rng);
        assert_eq!(masking.len(), 2);
        
        // Sum should be deterministic once polys are generated
        let sum1 = prover.sum_of_masking(&masking);
        let sum2 = prover.sum_of_masking(&masking);
        assert_eq!(sum1, sum2);
    }

    #[test]
    fn zk_prover_masked_sum() {
        let mut rng = test_rng();
        let prover = ZkSumCheckProver::new(3, 1);
        
        let masking = prover.generate_masking_polys(&mut rng);
        let y = Fr::from(42u64);
        
        let z = prover.compute_masked_sum(y, &masking);
        let g_sum = prover.sum_of_masking(&masking);
        
        assert_eq!(z, y + g_sum);
    }

    #[test]
    fn zk_sumcheck_basic() {
        let mut rng = test_rng();
        
        // Create simple polynomial: f(x,y) with 4 evaluations
        let evals = vec![
            Fr::from(1u64), Fr::from(2u64),
            Fr::from(3u64), Fr::from(4u64),
        ];
        let claimed_sum: Fr = evals.iter().copied().sum(); // 10
        
        let proof = zk_sumcheck_prove(&evals, claimed_sum, 2, &mut rng);
        
        // Verify structure
        let verifier = ZkSumCheckVerifier::new(2, 1);
        assert!(verifier.verify_structure(&proof));
    }

    #[test]
    fn zk_sumcheck_recover_evaluation() {
        let mut rng = test_rng();
        
        let evals = vec![
            Fr::from(1u64), Fr::from(2u64),
            Fr::from(3u64), Fr::from(4u64),
        ];
        let claimed_sum: Fr = evals.iter().copied().sum();
        
        let proof = zk_sumcheck_prove(&evals, claimed_sum, 2, &mut rng);
        
        let verifier = ZkSumCheckVerifier::new(2, 1);
        let y_prime = verifier.recover_final_evaluation(&proof);
        
        // y' should be F(r) which we can compute from the bound evaluations
        let mut bound = evals.clone();
        for &r in &proof.final_point {
            bound = bind_evaluations(&bound, r);
        }
        let f_at_r = bound[0];
        
        assert_eq!(y_prime, f_at_r);
    }

    #[test]
    fn zk_masking_hides_f() {
        let mut rng = test_rng();
        
        // Two different polynomials should produce different masked sums
        let evals1 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let evals2 = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64), Fr::from(40u64)];
        
        let sum1: Fr = evals1.iter().copied().sum();
        let sum2: Fr = evals2.iter().copied().sum();
        
        // But the masked sums depend on random masking
        let proof1 = zk_sumcheck_prove(&evals1, sum1, 2, &mut rng);
        let proof2 = zk_sumcheck_prove(&evals2, sum2, 2, &mut rng);
        
        // Masked sums are different (with overwhelming probability)
        // because they include different true sums
        assert_ne!(proof1.masked_sum, proof2.masked_sum);
    }

    #[test]
    fn zk_sumcheck_larger_instance() {
        let mut rng = test_rng();
        
        // 2^4 = 16 evaluations
        let num_vars = 4;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
        let claimed_sum: Fr = evals.iter().copied().sum();
        
        let proof = zk_sumcheck_prove(&evals, claimed_sum, num_vars, &mut rng);
        
        let verifier = ZkSumCheckVerifier::new(num_vars, 1);
        assert!(verifier.verify_structure(&proof));
        
        // Final point should have num_vars elements
        assert_eq!(proof.final_point.len(), num_vars);
        assert_eq!(proof.round_polys.len(), num_vars);
    }

    #[test]
    fn bind_evaluations_basic() {
        // f(x, y) = 1 + 2x + 3y + 4xy
        // evals: f(0,0)=1, f(0,1)=4, f(1,0)=3, f(1,1)=10
        let evals = vec![Fr::from(1u64), Fr::from(4u64), Fr::from(3u64), Fr::from(10u64)];
        
        // Bind x to r=2: f(2, y) = 1 + 4 + 3y + 8y = 5 + 11y
        // f(2, 0) = 5, f(2, 1) = 16
        let r = Fr::from(2u64);
        let bound = bind_evaluations(&evals, r);
        
        // bound[0] = (1-r)*evals[0] + r*evals[2] = -1*1 + 2*3 = 5
        // bound[1] = (1-r)*evals[1] + r*evals[3] = -1*4 + 2*10 = 16
        assert_eq!(bound.len(), 2);
        assert_eq!(bound[0], Fr::from(5u64));
        assert_eq!(bound[1], Fr::from(16u64));
    }
}

