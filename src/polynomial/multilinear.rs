//! Multilinear polynomial with dense representation over {0,1}^ℓ

use crate::polynomial::eq_polynomial;
use ark_ff::Field;
use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct MultilinearPolynomial<F: Field> {
    pub evaluations: Vec<F>, // dense evaluations over Boolean hypercube
    pub num_vars: usize,     // ℓ
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create from evaluations; len must be 2^ℓ
    pub fn from_evaluations(evaluations: Vec<F>, num_vars: usize) -> Self {
        let expected = 1usize << num_vars;
        assert_eq!(evaluations.len(), expected, "evaluation length must be 2^ℓ");
        Self { evaluations, num_vars }
    }

    /// Evaluate at Boolean point e ∈ {0,1}^ℓ (given as bools)
    pub fn eval_boolean(&self, e: &[bool]) -> F {
        assert_eq!(e.len(), self.num_vars);
        // index from bits
        let mut idx = 0usize;
        for &b in e {
            idx = (idx << 1) | if b { 1 } else { 0 };
        }
        self.evaluations[idx]
    }

    /// Evaluate MLE at arbitrary point x ∈ F^ℓ in O(2^ℓ)
    /// Uses parallel evaluation for large polynomials (threshold: 2^10 = 1024 evaluations)
    pub fn evaluate(&self, x: &[F]) -> F {
        assert_eq!(x.len(), self.num_vars);
        
        const PARALLEL_THRESHOLD: usize = 1024; // 2^10
        
        if self.evaluations.len() >= PARALLEL_THRESHOLD {
            // Parallel evaluation for large polynomials
            self.evaluate_parallel(x)
        } else {
            // Sequential evaluation for small polynomials (less overhead)
            self.evaluate_sequential(x)
        }
    }
    
    /// Sequential MLE evaluation (used for small polynomials)
    fn evaluate_sequential(&self, x: &[F]) -> F {
        let mut acc = F::zero();
        for idx in 0..self.evaluations.len() {
            let mut bits = Vec::with_capacity(self.num_vars);
            for i in 0..self.num_vars {
                let bit = ((idx >> (self.num_vars - 1 - i)) & 1) == 1;
                bits.push(bit);
            }
            let weight = eq_polynomial(x, &bits);
            acc += self.evaluations[idx] * weight;
        }
        acc
    }
    
    /// Parallel MLE evaluation using rayon (used for large polynomials)
    fn evaluate_parallel(&self, x: &[F]) -> F {
        // Parallel sum over Boolean hypercube
        (0..self.evaluations.len())
            .into_par_iter()
            .map(|idx| {
                let mut bits = Vec::with_capacity(self.num_vars);
                for i in 0..self.num_vars {
                    let bit = ((idx >> (self.num_vars - 1 - i)) & 1) == 1;
                    bits.push(bit);
                }
                let weight = eq_polynomial(x, &bits);
                self.evaluations[idx] * weight
            })
            .reduce(|| F::zero(), |a, b| a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use ark_std::test_rng;
    use rand::Rng;
    use ark_ff::{One, Zero};

    #[test]
    fn mle_matches_on_boolean_cube() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);

        for idx in 0..size {
            // build Boolean vector for idx
            let mut bits = Vec::with_capacity(num_vars);
            for i in 0..num_vars {
                let bit = ((idx >> (num_vars - 1 - i)) & 1) == 1;
                bits.push(bit);
            }
            let x: Vec<Fr> = bits.iter().map(|&b| if b { Fr::one() } else { Fr::zero() }).collect();
            let mle_val = poly.evaluate(&x);
            assert_eq!(mle_val, evals[idx]);
        }
    }

    #[test]
    fn linearity_property() {
        let mut rng = test_rng();
        let num_vars = 2;
        let size = 1usize << num_vars;

        let f_eval: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let g_eval: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();

        let f = MultilinearPolynomial::from_evaluations(f_eval.clone(), num_vars);
        let g = MultilinearPolynomial::from_evaluations(g_eval.clone(), num_vars);

        let mut h_eval = Vec::with_capacity(size);
        for i in 0..size {
            h_eval.push(f_eval[i] + g_eval[i]);
        }
        let h = MultilinearPolynomial::from_evaluations(h_eval, num_vars);

        // random point
        for _ in 0..20 {
            let x: Vec<Fr> = (0..num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
            let lhs = h.evaluate(&x);
            let rhs = f.evaluate(&x) + g.evaluate(&x);
            assert_eq!(lhs, rhs);
        }
    }
}

