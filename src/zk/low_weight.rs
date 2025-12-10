//! Low-weight Polynomials (Definition 8.1)
//!
//! g(X) = b₀·∏ᵢ(1-Xᵢ) + Σᵢbᵢ(2Xᵢ-1)·∏_{j≠i}(1-Xⱼ)
//!
//! Properties:
//! - Support on {0,1}^ℓ is contained in {(0,...,0), e₁,...,eℓ}
//! - g(0,...,0) = b₀ - Σᵢbᵢ
//! - g(eᵢ) = bᵢ
//! - Binding preserves low-weight form (Lemma 8.3)

use ark_bls12_381::Fr;
use ark_ff::{Zero, One};
use ark_std::vec::Vec;
use ark_std::rand::RngCore;
use ark_ff::UniformRand;

/// Low-weight polynomial in ℓ variables
/// 
/// Represented by coefficients b = (b₀, b₁, ..., bℓ)
#[derive(Clone, Debug)]
pub struct LowWeightPolynomial {
    /// Coefficients b₀, b₁, ..., bℓ
    pub coeffs: Vec<Fr>,
    /// Number of variables ℓ
    pub num_vars: usize,
}

impl LowWeightPolynomial {
    /// Create a new low-weight polynomial from coefficients
    pub fn new(coeffs: Vec<Fr>) -> Self {
        let num_vars = coeffs.len() - 1;
        Self { coeffs, num_vars }
    }

    /// Sample a uniformly random low-weight polynomial
    pub fn random<R: RngCore>(num_vars: usize, rng: &mut R) -> Self {
        let coeffs: Vec<Fr> = (0..=num_vars).map(|_| Fr::rand(rng)).collect();
        Self { coeffs, num_vars }
    }

    /// Evaluate g(X) at a point x ∈ F^ℓ
    /// 
    /// g(X) = b₀·∏ᵢ(1-Xᵢ) + Σᵢbᵢ(2Xᵢ-1)·∏_{j≠i}(1-Xⱼ)
    pub fn evaluate(&self, x: &[Fr]) -> Fr {
        assert_eq!(x.len(), self.num_vars, "Point dimension mismatch");
        
        let one = Fr::one();
        let two = Fr::from(2u64);
        
        // Compute ∏ᵢ(1-Xᵢ)
        let prod_all: Fr = x.iter()
            .map(|xi| one - *xi)
            .fold(Fr::one(), |acc, v| acc * v);
        
        // First term: b₀·∏ᵢ(1-Xᵢ)
        let mut result = self.coeffs[0] * prod_all;
        
        // Sum terms: Σᵢbᵢ(2Xᵢ-1)·∏_{j≠i}(1-Xⱼ)
        for i in 0..self.num_vars {
            // Compute (2Xᵢ-1)
            let factor = two * x[i] - one;
            
            // Compute ∏_{j≠i}(1-Xⱼ)
            let prod_except_i: Fr = x.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, xj)| one - *xj)
                .fold(Fr::one(), |acc, v| acc * v);
            
            result += self.coeffs[i + 1] * factor * prod_except_i;
        }
        
        result
    }

    /// Evaluate g at (0, ..., 0)
    /// 
    /// Lemma 8.1: g(0,...,0) = b₀ - Σᵢbᵢ
    pub fn eval_at_zero(&self) -> Fr {
        let sum_b: Fr = self.coeffs[1..].iter().copied().sum();
        self.coeffs[0] - sum_b
    }

    /// Evaluate g at eᵢ (i-th unit vector)
    /// 
    /// Lemma 8.1: g(eᵢ) = bᵢ
    pub fn eval_at_unit(&self, i: usize) -> Fr {
        assert!(i < self.num_vars, "Unit vector index out of bounds");
        self.coeffs[i + 1]
    }

    /// Evaluate g on the full Boolean hypercube {0,1}^ℓ
    /// 
    /// Returns evaluations at all 2^ℓ points.
    /// Non-support points (more than one 1) evaluate to 0.
    pub fn eval_on_hypercube(&self) -> Vec<Fr> {
        let size = 1usize << self.num_vars;
        let mut evals = vec![Fr::zero(); size];
        
        // Evaluate at (0, ..., 0) which is index 0
        evals[0] = self.eval_at_zero();
        
        // Evaluate at each unit vector eᵢ
        for i in 0..self.num_vars {
            let idx = 1 << (self.num_vars - 1 - i);
            evals[idx] = self.coeffs[i + 1];
        }
        
        // All other points have support outside {0,...,0} ∪ {eᵢ}
        // so they evaluate to 0 (already initialized)
        
        evals
    }

    /// Sum over the Boolean hypercube
    /// 
    /// Σ_{x∈{0,1}^ℓ} g(x) = g(0,...,0) + Σᵢg(eᵢ)
    ///                    = (b₀ - Σbᵢ) + Σbᵢ = b₀
    pub fn sum_over_hypercube(&self) -> Fr {
        self.coeffs[0]
    }

    /// Bind the first variable to r
    /// 
    /// Lemma 8.3: g(r, X) is still low-weight with:
    /// - b₀' = b₀(1-r) + (2r-1)b₁
    /// - bᵢ' = b_{i+1}(1-r) for i ≥ 1
    pub fn bind(&self, r: Fr) -> Self {
        let one = Fr::one();
        let two = Fr::from(2u64);
        
        let mut new_coeffs = Vec::with_capacity(self.num_vars);
        
        // b₀' = b₀(1-r) + (2r-1)b₁
        let b0_new = self.coeffs[0] * (one - r) + (two * r - one) * self.coeffs[1];
        new_coeffs.push(b0_new);
        
        // bᵢ' = b_{i+1}(1-r) for i ≥ 1
        for i in 2..=self.num_vars {
            new_coeffs.push(self.coeffs[i] * (one - r));
        }
        
        Self {
            coeffs: new_coeffs,
            num_vars: self.num_vars - 1,
        }
    }

    /// Sum over hypercube in first variable
    /// 
    /// Lemma 8.2: Σ_{x∈{0,1}^{ℓ-1}} g(X, x) = (b₀ - b₁) + (2b₁ - b₀)X
    /// 
    /// Returns (c₀, c₁) such that the result is c₀ + c₁·X
    pub fn sum_first_var(&self) -> (Fr, Fr) {
        let b0 = self.coeffs[0];
        let b1 = self.coeffs[1];
        let two = Fr::from(2u64);
        
        let c0 = b0 - b1;
        let c1 = two * b1 - b0;
        
        (c0, c1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn low_weight_eval_at_zero() {
        // g with b = (10, 2, 3, 4) for ℓ=3
        // g(0,0,0) = 10 - (2+3+4) = 1
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);
        
        let at_zero = g.eval_at_zero();
        assert_eq!(at_zero, Fr::from(1u64));
        
        // Verify using evaluate
        let zero_point = vec![Fr::zero(), Fr::zero(), Fr::zero()];
        assert_eq!(g.evaluate(&zero_point), at_zero);
    }

    #[test]
    fn low_weight_eval_at_unit() {
        // g with b = (10, 2, 3, 4) for ℓ=3
        // g(e₀) = b₁ = 2, g(e₁) = b₂ = 3, g(e₂) = b₃ = 4
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);
        
        assert_eq!(g.eval_at_unit(0), Fr::from(2u64));
        assert_eq!(g.eval_at_unit(1), Fr::from(3u64));
        assert_eq!(g.eval_at_unit(2), Fr::from(4u64));
        
        // Verify using evaluate
        let e0 = vec![Fr::one(), Fr::zero(), Fr::zero()];
        let e1 = vec![Fr::zero(), Fr::one(), Fr::zero()];
        let e2 = vec![Fr::zero(), Fr::zero(), Fr::one()];
        
        assert_eq!(g.evaluate(&e0), Fr::from(2u64));
        assert_eq!(g.evaluate(&e1), Fr::from(3u64));
        assert_eq!(g.evaluate(&e2), Fr::from(4u64));
    }

    #[test]
    fn low_weight_support_property() {
        // Lemma 8.1: Support is {(0,...,0), e₁,...,eℓ}
        // Points with 2+ ones should evaluate to 0
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ]);
        
        // (1, 1) should be 0
        let point = vec![Fr::one(), Fr::one()];
        assert_eq!(g.evaluate(&point), Fr::zero());
    }

    #[test]
    fn low_weight_sum_over_hypercube() {
        // Σ g(x) = b₀
        let g = LowWeightPolynomial::new(vec![
            Fr::from(42u64),
            Fr::from(5u64),
            Fr::from(7u64),
        ]);
        
        assert_eq!(g.sum_over_hypercube(), Fr::from(42u64));
        
        // Verify by explicit summation
        let evals = g.eval_on_hypercube();
        let sum: Fr = evals.iter().copied().sum();
        assert_eq!(sum, Fr::from(42u64));
    }

    #[test]
    fn low_weight_bind_basic() {
        // After binding first var to r, result should still be low-weight
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);
        
        let r = Fr::from(5u64);
        let g_bound = g.bind(r);
        
        assert_eq!(g_bound.num_vars, 2);
        
        // Verify g(r, x) = g_bound(x) for some x
        let test_x = vec![Fr::from(7u64), Fr::from(11u64)];
        let full_point = vec![r, test_x[0], test_x[1]];
        
        let expected = g.evaluate(&full_point);
        let actual = g_bound.evaluate(&test_x);
        
        assert_eq!(actual, expected);
    }

    #[test]
    fn low_weight_sum_first_var() {
        // Lemma 8.2: Σ_{x∈{0,1}^{ℓ-1}} g(X, x) = (b₀ - b₁) + (2b₁ - b₀)X
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(3u64),
            Fr::from(5u64),
        ]);
        
        let (c0, c1) = g.sum_first_var();
        
        // c0 = 10 - 3 = 7
        // c1 = 2*3 - 10 = -4
        assert_eq!(c0, Fr::from(7u64));
        assert_eq!(c1, Fr::from(6u64) - Fr::from(10u64)); // -4 in field
        
        // Verify: result(X) = Σ_{y∈{0,1}} g(X, y)
        // At X=0: should be c0 = 7
        // At X=1: should be c0 + c1 = 7 - 4 = 3
        
        // Sum g(0, y) for y ∈ {0,1}
        let sum_at_0 = g.evaluate(&vec![Fr::zero(), Fr::zero()])
            + g.evaluate(&vec![Fr::zero(), Fr::one()]);
        assert_eq!(sum_at_0, c0);
        
        // Sum g(1, y) for y ∈ {0,1}
        let sum_at_1 = g.evaluate(&vec![Fr::one(), Fr::zero()])
            + g.evaluate(&vec![Fr::one(), Fr::one()]);
        assert_eq!(sum_at_1, c0 + c1);
    }

    #[test]
    fn low_weight_random_sum_property() {
        // Random low-weight should still have sum = b₀
        let mut rng = test_rng();
        
        for _ in 0..10 {
            let g = LowWeightPolynomial::random(4, &mut rng);
            let evals = g.eval_on_hypercube();
            let sum: Fr = evals.iter().copied().sum();
            
            assert_eq!(sum, g.coeffs[0]);
        }
    }

    #[test]
    fn low_weight_bind_chain() {
        // Binding variables one by one should work
        let mut rng = test_rng();
        let g = LowWeightPolynomial::random(4, &mut rng);
        
        let r: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        
        // Bind one by one
        let g1 = g.bind(r[0]);
        let g2 = g1.bind(r[1]);
        let g3 = g2.bind(r[2]);
        let g4 = g3.bind(r[3]);
        
        assert_eq!(g4.num_vars, 0);
        
        // Final value should match g(r)
        let expected = g.evaluate(&r);
        let actual = g4.coeffs[0]; // Single coefficient for 0-var polynomial
        
        assert_eq!(actual, expected);
    }

    #[test]
    fn low_weight_eval_on_hypercube() {
        let g = LowWeightPolynomial::new(vec![
            Fr::from(10u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ]);
        
        let evals = g.eval_on_hypercube();
        
        // Size should be 2^2 = 4
        assert_eq!(evals.len(), 4);
        
        // evals[0] = g(0,0) = 10 - 5 = 5
        assert_eq!(evals[0], Fr::from(5u64));
        
        // evals[2] = g(1,0) = 2 (first unit vector, b₁)
        assert_eq!(evals[2], Fr::from(2u64));
        
        // evals[1] = g(0,1) = 3 (second unit vector, b₂)
        assert_eq!(evals[1], Fr::from(3u64));
        
        // evals[3] = g(1,1) = 0 (not in support)
        assert_eq!(evals[3], Fr::zero());
    }
}

