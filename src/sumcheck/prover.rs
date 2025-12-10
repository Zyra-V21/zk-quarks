use ark_ff::Field;

use crate::polynomial::MultilinearPolynomial;
use super::univariate::UnivariateDegree1;

/// Prover for the sum-check protocol over a multilinear polynomial
pub struct SumCheckProver<F: Field> {
    poly: MultilinearPolynomial<F>,
    round: usize,
}

impl<F: Field> SumCheckProver<F> {
    pub fn new(poly: MultilinearPolynomial<F>) -> Self {
        Self { poly, round: 0 }
    }

    pub fn num_vars(&self) -> usize {
        self.poly.num_vars
    }

    /// Compute g_i(X) = Σ_{rest} G(prefix, X, rest)
    /// For multilinear polynomials, g_i is degree 1: g_i(t) = c0 + (c1 - c0) * t
    /// prefix contains the verifier challenges r_1 .. r_i (field elements)
    pub fn next_message(&mut self, prefix: &[F]) -> UnivariateDegree1<F> {
        assert_eq!(prefix.len(), self.round, "prefix length must match round");
        let _var_idx = self.round;
        let mut sum0 = F::zero();
        let mut sum1 = F::zero();
        let rest = self.poly.num_vars - prefix.len() - 1;

        // Enumerate all assignments to remaining variables (Boolean)
        let total_rest = 1usize << rest;
        for mask in 0..total_rest {
            // build point for current var = 0
            let mut point0 = Vec::with_capacity(self.poly.num_vars);
            point0.extend_from_slice(prefix);
            point0.push(F::zero());
            for j in 0..rest {
                let bit = (mask >> (rest - 1 - j)) & 1 == 1;
                point0.push(if bit { F::one() } else { F::zero() });
            }
            sum0 += self.poly.evaluate(&point0);

            // current var = 1
            let mut point1 = Vec::with_capacity(self.poly.num_vars);
            point1.extend_from_slice(prefix);
            point1.push(F::one());
            for j in 0..rest {
                let bit = (mask >> (rest - 1 - j)) & 1 == 1;
                point1.push(if bit { F::one() } else { F::zero() });
            }
            sum1 += self.poly.evaluate(&point1);
        }

        // g(t) = sum0 + (sum1 - sum0) * t
        let c0 = sum0;
        let c1 = sum1 - sum0;
        self.round += 1;
        UnivariateDegree1 { c0, c1 }
    }

    /// Prover returns final evaluation G(r)
    pub fn final_evaluation(&self, r: &[F]) -> F {
        self.poly.evaluate(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use ark_std::test_rng;
    use rand::Rng;
    use ark_ff::Zero;

    #[test]
    fn prover_univariate_degree1() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 7)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);
        let mut prover = SumCheckProver::new(poly);

        // Round 0: no prefix
        let g0 = prover.next_message(&[]);
        // g0(0) + g0(1) must equal total sum
        assert_eq!(g0.sum_over_boolean(), claimed_sum);

        // choose random r0
        let r0 = Fr::from(rng.gen::<u64>() % 7);
        let s1 = g0.evaluate(r0);

        // Round 1: prefix [r0]
        let g1 = prover.next_message(&[r0]);
        assert_eq!(g1.sum_over_boolean(), s1);
    }
}

