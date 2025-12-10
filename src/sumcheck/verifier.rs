use ark_ff::Field;
use ark_std::rand::Rng;

use super::univariate::UnivariateDegree1;

#[derive(Debug)]
pub struct RoundClaim<F: Field> {
    pub poly: UnivariateDegree1<F>,
    pub expected_sum: F,
}

/// Verifier for sum-check. Maintains current target sum and random challenges.
pub struct SumCheckVerifier<F: Field, R: Rng> {
    pub current_sum: F,
    pub challenges: Vec<F>,
    pub rng: R,
    pub num_vars: usize,
}

impl<F: Field, R: Rng> SumCheckVerifier<F, R> {
    pub fn new(initial_sum: F, num_vars: usize, rng: R) -> Self {
        Self {
            current_sum: initial_sum,
            challenges: Vec::with_capacity(num_vars),
            rng,
            num_vars,
        }
    }

    /// Verify a single round message g_i. Returns new target sum and records challenge.
    pub fn verify_round(&mut self, msg: &RoundClaim<F>) -> bool {
        // Check g_i(0) + g_i(1) = current_sum
        if msg.poly.sum_over_boolean() != self.current_sum {
            return false;
        }
        // Sample random r_i
        let ri = F::from(self.rng.gen::<u64>());
        self.challenges.push(ri);
        // Update target sum s = g_i(r_i)
        self.current_sum = msg.poly.evaluate(ri);
        true
    }

    /// After all rounds, verifier expects prover to provide G(r) value; verifier checks equality
    pub fn finalize(&self, claimed_eval: F) -> bool {
        claimed_eval == self.current_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Zero, One};
    use crate::polynomial::MultilinearPolynomial;
    use crate::field::Bls12381Fr as Fr;
    use crate::sumcheck::prover::SumCheckProver;
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn sumcheck_end_to_end() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 5)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);

        let mut prover = SumCheckProver::new(poly.clone());
        let mut verifier = SumCheckVerifier::new(claimed_sum, num_vars, test_rng());

        for _ in 0..num_vars {
            let prefix: Vec<Fr> = verifier.challenges.clone();
            let msg_poly = prover.next_message(&prefix);
            let claim = RoundClaim { poly: msg_poly, expected_sum: verifier.current_sum };
            assert!(verifier.verify_round(&claim));
        }
        // Prover sends final evaluation G(r)
        let final_eval = poly.evaluate(&verifier.challenges);
        assert!(verifier.finalize(final_eval));
    }

    #[test]
    fn sumcheck_reject_wrong_sum() {
        let mut rng = test_rng();
        let num_vars = 2;
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 5)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);

        let mut prover = SumCheckProver::new(poly);
        let mut verifier = SumCheckVerifier::new(claimed_sum, num_vars, test_rng());

        // Round 0
        let msg_poly = prover.next_message(&[]);
        let mut claim = RoundClaim { poly: msg_poly, expected_sum: verifier.current_sum };
        assert!(verifier.verify_round(&claim));

        // Round 1 with tampered polynomial
        let bad_poly = UnivariateDegree1 { c0: Fr::one(), c1: Fr::one() };
        claim = RoundClaim { poly: bad_poly, expected_sum: verifier.current_sum };
        assert!(!verifier.verify_round(&claim));
    }
}

