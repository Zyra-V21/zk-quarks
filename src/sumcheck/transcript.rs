//! Fiat-Shamir transcript for non-interactive sum-check
//!
//! Converts the interactive sum-check protocol to a NIZK by deriving
//! verifier challenges from a hash of the protocol transcript.
//!
//! Uses a simple sponge-like construction over the field.

use ark_ff::{Field, PrimeField};
use ark_std::vec::Vec;

/// Transcript for Fiat-Shamir transformation
/// Accumulates protocol messages and derives challenges deterministically
#[derive(Clone, Debug)]
pub struct Transcript<F: Field> {
    /// Accumulated field elements (messages)
    state: Vec<F>,
    /// Domain separator for different protocol instances
    label: Vec<u8>,
    /// Counter for challenge generation
    challenge_counter: u64,
}

impl<F: PrimeField> Transcript<F> {
    /// Create new transcript with a domain separator label
    pub fn new(label: &[u8]) -> Self {
        Self {
            state: Vec::new(),
            label: label.to_vec(),
            challenge_counter: 0,
        }
    }

    /// Append a field element to the transcript
    pub fn append_scalar(&mut self, scalar: F) {
        self.state.push(scalar);
    }

    /// Append multiple field elements
    pub fn append_scalars(&mut self, scalars: &[F]) {
        self.state.extend_from_slice(scalars);
    }

    /// Append a message label (converted to field element via hash)
    pub fn append_message(&mut self, label: &[u8]) {
        // Simple conversion: sum of bytes as field element
        let sum: u64 = label.iter().map(|&b| b as u64).sum();
        self.state.push(F::from(sum));
    }

    /// Derive a challenge from the current transcript state
    /// Uses a simple hash-like construction: 
    /// challenge = H(label || state || counter)
    pub fn challenge(&mut self) -> F {
        // Simple but deterministic challenge derivation
        // In production, use a proper hash function (Poseidon, Blake3, etc.)
        let mut acc = F::zero();
        
        // Mix in label
        for &byte in &self.label {
            acc += F::from(byte as u64);
            acc = acc.square() + acc;
        }
        
        // Mix in all state elements
        for elem in &self.state {
            acc += *elem;
            acc = acc.square() + acc;
        }
        
        // Mix in counter
        acc += F::from(self.challenge_counter);
        acc = acc.square() + acc;
        
        self.challenge_counter += 1;
        
        // Add the challenge to state so future challenges depend on it
        self.state.push(acc);
        
        acc
    }

    /// Derive multiple challenges
    pub fn challenges(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.challenge()).collect()
    }

    /// Reset the transcript (keeping the label)
    pub fn reset(&mut self) {
        self.state.clear();
        self.challenge_counter = 0;
    }
}

/// Non-interactive sum-check proof
#[derive(Clone, Debug)]
pub struct SumCheckProof<F: Field> {
    /// Round polynomials g_i represented as (c0, c1) pairs
    /// g_i(t) = c0 + c1 * t
    pub round_polys: Vec<(F, F)>,
    /// Final evaluation claim
    pub final_eval: F,
}

impl<F: PrimeField> SumCheckProof<F> {
    /// Verify the sum-check proof non-interactively
    /// Returns (accept, random_point) where random_point = (r_1, ..., r_ℓ)
    pub fn verify(
        &self,
        claimed_sum: F,
        num_vars: usize,
        transcript: &mut Transcript<F>,
    ) -> Result<(bool, Vec<F>), &'static str> {
        if self.round_polys.len() != num_vars {
            return Err("wrong number of round polynomials");
        }

        let mut current_sum = claimed_sum;
        let mut challenges = Vec::with_capacity(num_vars);

        for &(c0, c1) in self.round_polys.iter() {
            // Append round polynomial to transcript
            transcript.append_scalar(c0);
            transcript.append_scalar(c1);

            // Check: g_i(0) + g_i(1) = current_sum
            // g(0) = c0, g(1) = c0 + c1
            // sum = 2*c0 + c1
            let sum_01 = c0.double() + c1;
            if sum_01 != current_sum {
                return Ok((false, challenges));
            }

            // Derive challenge r_i from transcript
            let r_i = transcript.challenge();
            challenges.push(r_i);

            // Update: current_sum = g_i(r_i) = c0 + c1 * r_i
            current_sum = c0 + c1 * r_i;
        }

        // Final check: claimed evaluation at random point
        if self.final_eval != current_sum {
            return Ok((false, challenges));
        }

        Ok((true, challenges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use crate::polynomial::MultilinearPolynomial;
    use ark_std::test_rng;
    use rand::Rng;
    use ark_ff::Zero;

    #[test]
    fn transcript_deterministic() {
        let mut t1 = Transcript::<Fr>::new(b"test");
        let mut t2 = Transcript::<Fr>::new(b"test");

        t1.append_scalar(Fr::from(42u64));
        t2.append_scalar(Fr::from(42u64));

        let c1 = t1.challenge();
        let c2 = t2.challenge();

        assert_eq!(c1, c2, "same inputs should give same challenge");
    }

    #[test]
    fn transcript_different_inputs() {
        let mut t1 = Transcript::<Fr>::new(b"test");
        let mut t2 = Transcript::<Fr>::new(b"test");

        t1.append_scalar(Fr::from(42u64));
        t2.append_scalar(Fr::from(43u64));

        let c1 = t1.challenge();
        let c2 = t2.challenge();

        assert_ne!(c1, c2, "different inputs should give different challenges");
    }

    #[test]
    fn transcript_different_labels() {
        let mut t1 = Transcript::<Fr>::new(b"test1");
        let mut t2 = Transcript::<Fr>::new(b"test2");

        t1.append_scalar(Fr::from(42u64));
        t2.append_scalar(Fr::from(42u64));

        let c1 = t1.challenge();
        let c2 = t2.challenge();

        assert_ne!(c1, c2, "different labels should give different challenges");
    }

    /// Generate a non-interactive sum-check proof
    fn prove_sumcheck(
        poly: &MultilinearPolynomial<Fr>,
        transcript: &mut Transcript<Fr>,
    ) -> SumCheckProof<Fr> {
        let num_vars = poly.num_vars;
        let mut round_polys = Vec::with_capacity(num_vars);
        let mut challenges = Vec::with_capacity(num_vars);

        for round in 0..num_vars {
            let rest = num_vars - round - 1;
            let total_rest = 1usize << rest;

            let mut sum0 = Fr::zero();
            let mut sum1 = Fr::zero();

            for mask in 0..total_rest {
                // Build point with current var = 0
                let mut point0 = Vec::with_capacity(num_vars);
                point0.extend_from_slice(&challenges);
                point0.push(Fr::zero());
                for j in 0..rest {
                    let bit = (mask >> (rest - 1 - j)) & 1 == 1;
                    point0.push(if bit { Fr::from(1u64) } else { Fr::zero() });
                }
                sum0 += poly.evaluate(&point0);

                // Build point with current var = 1
                let mut point1 = Vec::with_capacity(num_vars);
                point1.extend_from_slice(&challenges);
                point1.push(Fr::from(1u64));
                for j in 0..rest {
                    let bit = (mask >> (rest - 1 - j)) & 1 == 1;
                    point1.push(if bit { Fr::from(1u64) } else { Fr::zero() });
                }
                sum1 += poly.evaluate(&point1);
            }

            let c0 = sum0;
            let c1 = sum1 - sum0;

            // Append to transcript and get challenge
            transcript.append_scalar(c0);
            transcript.append_scalar(c1);
            let r_i = transcript.challenge();

            round_polys.push((c0, c1));
            challenges.push(r_i);
        }

        let final_eval = poly.evaluate(&challenges);

        SumCheckProof {
            round_polys,
            final_eval,
        }
    }

    #[test]
    fn sumcheck_nizk_complete() {
        let mut rng = test_rng();
        let num_vars = 4;
        let size = 1usize << num_vars;

        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 100)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);

        // Prover generates proof
        let mut prover_transcript = Transcript::new(b"sumcheck");
        let proof = prove_sumcheck(&poly, &mut prover_transcript);

        // Verifier checks proof with fresh transcript (same label)
        let mut verifier_transcript = Transcript::new(b"sumcheck");
        let (accept, r) = proof.verify(claimed_sum, num_vars, &mut verifier_transcript).unwrap();

        assert!(accept, "honest proof should be accepted");
        assert_eq!(r.len(), num_vars);

        // Verify final evaluation is correct
        assert_eq!(poly.evaluate(&r), proof.final_eval);
    }

    #[test]
    fn sumcheck_nizk_soundness_wrong_sum() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;

        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 100)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let correct_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);
        let wrong_sum = correct_sum + Fr::from(1u64);

        // Prover generates proof for CORRECT sum
        let mut prover_transcript = Transcript::new(b"sumcheck");
        let proof = prove_sumcheck(&poly, &mut prover_transcript);

        // Verifier tries to verify against WRONG sum
        let mut verifier_transcript = Transcript::new(b"sumcheck");
        let (accept, _) = proof.verify(wrong_sum, num_vars, &mut verifier_transcript).unwrap();

        assert!(!accept, "wrong sum should be rejected");
    }

    #[test]
    fn sumcheck_nizk_soundness_tampered_proof() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;

        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 100)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);

        // Prover generates honest proof
        let mut prover_transcript = Transcript::new(b"sumcheck");
        let mut proof = prove_sumcheck(&poly, &mut prover_transcript);

        // Tamper with the proof
        if let Some((c0, _c1)) = proof.round_polys.get_mut(0) {
            *c0 += Fr::from(1u64);
        }

        // Verifier should reject
        let mut verifier_transcript = Transcript::new(b"sumcheck");
        let (accept, _) = proof.verify(claimed_sum, num_vars, &mut verifier_transcript).unwrap();

        assert!(!accept, "tampered proof should be rejected");
    }

    #[test]
    fn sumcheck_nizk_multiple_runs_same_result() {
        let mut rng = test_rng();
        let num_vars = 3;
        let size = 1usize << num_vars;

        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 100)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);
        let claimed_sum = evals.iter().copied().fold(Fr::zero(), |a, b| a + b);

        // Generate proof twice - should be identical
        let mut t1 = Transcript::new(b"sumcheck");
        let proof1 = prove_sumcheck(&poly, &mut t1);

        let mut t2 = Transcript::new(b"sumcheck");
        let proof2 = prove_sumcheck(&poly, &mut t2);

        assert_eq!(proof1.round_polys, proof2.round_polys);
        assert_eq!(proof1.final_eval, proof2.final_eval);

        // Both proofs should verify
        let mut v1 = Transcript::new(b"sumcheck");
        let (ok1, _) = proof1.verify(claimed_sum, num_vars, &mut v1).unwrap();
        assert!(ok1);
    }

    #[test]
    fn communication_size_is_d_times_l() {
        // For sum-check over a single MLE (degree d=1 in each variable):
        // - Each round sends a degree-1 polynomial: 2 field elements (c0, c1)
        // - Total rounds: ℓ (num_vars)
        // - Communication: ℓ * 2 = O(d·ℓ) where d=1
        //
        // For degree d polynomials:
        // - Each round sends d+1 coefficients
        // - Communication: ℓ * (d+1) = O(d·ℓ)

        let mut rng = test_rng();

        // Test for various num_vars (ℓ)
        for num_vars in [2, 4, 6, 8, 10] {
            let size = 1usize << num_vars;
            let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>() % 100)).collect();
            let poly = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);

            let mut transcript = Transcript::new(b"sumcheck");
            let proof = prove_sumcheck(&poly, &mut transcript);

            // For MLE (d=1): each round polynomial has 2 coefficients
            let d = 1;
            let coeffs_per_round = d + 1; // 2 for d=1
            let expected_round_polys = num_vars;
            let expected_field_elements = num_vars * coeffs_per_round + 1; // +1 for final_eval

            assert_eq!(
                proof.round_polys.len(),
                expected_round_polys,
                "should have ℓ={} round polynomials",
                num_vars
            );

            // Each round poly is (c0, c1) = 2 field elements
            let actual_field_elements = proof.round_polys.len() * 2 + 1; // +1 for final_eval
            assert_eq!(
                actual_field_elements,
                expected_field_elements,
                "communication should be ℓ*(d+1)+1 = {}*{}+1 = {} field elements",
                num_vars,
                coeffs_per_round,
                expected_field_elements
            );

            // Verify O(d·ℓ) bound: actual ≤ c * d * ℓ for some constant c
            // Here c = 1 (plus the final eval which is O(1))
            assert!(
                actual_field_elements <= 2 * d * num_vars + 1,
                "communication {} exceeds O(d·ℓ) bound",
                actual_field_elements
            );
        }
    }
}

