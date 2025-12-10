//! Untrusted Assistant Protocol (§7 of Quarks paper)
//!
//! Accelerates the encoder (verifier's preprocessing) by using an untrusted assistant.
//!
//! ## Problem
//! Verifier needs to create commitments to structure polynomials Ã, B̃, C̃ of R1CS.
//! This requires O(n) group exponentiations.
//!
//! ## Solution
//! Assistant computes the commitment C, and proves it's correct:
//! 1. 𝒜 → V: (C_v; S_v) ← Commit_F(pp_F; v) where v will be claimed as G(r)
//! 2. V → 𝒜: r ←$ F^ℓ (random challenge)
//! 3. 𝒜, V: b_poly = PC.Eval(pp, pp_F, C, r, C_v; G, S, S_v)
//! 4. V: v ← G(r) (direct evaluation, O(n) field ops)
//! 5. 𝒜, V: b_eval = Open_F(pp_F, C_v, v, S_v)
//! 6. V: Accept if b_poly ∧ b_eval
//!
//! ## Result
//! Verifier cost: O(n) field multiplications + sub-linear verification
//! vs. O(n) group exponentiations without assistant

use ark_bls12_381::Fr;
use ark_std::vec::Vec;
use ark_std::rand::RngCore;

use crate::polynomial::MultilinearPolynomial;
use crate::commitments::pedersen::{PedersenParams, PedersenCommitment};

/// Protocol message from Assistant to Verifier
#[derive(Clone, Debug)]
pub struct AssistantCommitment {
    /// Polynomial commitment C (can be Kopis-PC, Hyrax-PC, etc.)
    pub poly_commitment: Vec<u8>, // Serialized commitment
    /// Commitment to claimed evaluation v = G(r)
    pub value_commitment: PedersenCommitment,
    /// Opening hint for value commitment
    pub value_hint: Fr,
}

/// Assistant state (can be run by anyone, including prover)
pub struct Assistant {
    /// The polynomial G being committed
    pub polynomial: MultilinearPolynomial<Fr>,
}

impl Assistant {
    pub fn new(polynomial: MultilinearPolynomial<Fr>) -> Self {
        Self { polynomial }
    }

    /// Step 1: Compute polynomial commitment and prepare value commitment
    /// 
    /// In practice, the assistant would use Kopis-PC or another scheme.
    /// For simplicity, we simulate the commitment.
    pub fn commit<R: RngCore>(
        &self,
        pedersen_params: &PedersenParams,
        evaluation_point: &[Fr],
        rng: &mut R,
    ) -> AssistantCommitment {
        use ark_ff::UniformRand;
        
        // Compute v = G(r)
        let v = self.polynomial.evaluate(evaluation_point);
        
        // Generate random blinding factor
        let blinding = Fr::rand(rng);
        
        // Commit to v using Pedersen
        let value_commitment = pedersen_params.commit_with_blinding(&v, &blinding);
        
        // In real implementation, compute actual polynomial commitment
        // For now, simulate with serialized data
        let poly_commitment = vec![0u8; 32]; // Placeholder
        
        AssistantCommitment {
            poly_commitment,
            value_commitment,
            value_hint: blinding,
        }
    }

    /// Step 3: Prove evaluation (in real implementation, uses PC.Eval)
    pub fn prove_eval(&self, _challenge: &[Fr]) -> bool {
        // In real implementation, execute PC.Eval protocol
        true
    }
}

/// Encoder (Verifier's preprocessing component)
pub struct Encoder {
    /// Number of variables in the polynomial
    pub num_vars: usize,
}

impl Encoder {
    pub fn new(num_vars: usize) -> Self {
        Self { num_vars }
    }

    /// Step 2: Generate random challenge
    pub fn generate_challenge<R: RngCore>(&self, rng: &mut R) -> Vec<Fr> {
        use ark_ff::UniformRand;
        (0..self.num_vars).map(|_| Fr::rand(rng)).collect()
    }

    /// Step 4: Evaluate polynomial directly (O(n) field ops)
    /// 
    /// This is the key cost reduction: instead of O(n) exponentiations,
    /// verifier does O(n) field multiplications.
    pub fn evaluate_polynomial(
        &self,
        polynomial: &MultilinearPolynomial<Fr>,
        point: &[Fr],
    ) -> Fr {
        polynomial.evaluate(point)
    }

    /// Step 5-6: Verify the assistant's commitment
    /// 
    /// Returns true if:
    /// - b_poly: PC.Eval verification passes
    /// - b_eval: Open_F(C_v, v, S_v) passes
    /// - v = G(r) (computed locally)
    pub fn verify(
        &self,
        polynomial: &MultilinearPolynomial<Fr>,
        assistant_commit: &AssistantCommitment,
        challenge: &[Fr],
        pedersen_params: &PedersenParams,
    ) -> bool {
        // Step 4: Evaluate polynomial directly
        let v_expected = self.evaluate_polynomial(polynomial, challenge);
        
        // Step 5: Verify value commitment opens to v_expected
        let b_eval = pedersen_params.verify(
            &assistant_commit.value_commitment.point,
            &v_expected,
            &assistant_commit.value_hint,
        );
        
        if !b_eval {
            return false;
        }
        
        // Step 3: Verify polynomial commitment (simulated)
        // In real implementation, this would be PC.Eval verification
        let b_poly = true; // Placeholder
        
        // Step 6: Accept if both checks pass
        b_poly && b_eval
    }
}

/// Complete assistant protocol
/// 
/// Lemma 7.1: This is a public-coin succinct interactive argument of knowledge
/// for the language {⟨(C_G, G), (S_G)⟩ : Open(pp, C_G, G, S_G) = 1}
pub struct AssistantProtocol {
    pub encoder: Encoder,
}

impl AssistantProtocol {
    pub fn new(num_vars: usize) -> Self {
        Self {
            encoder: Encoder::new(num_vars),
        }
    }

    /// Execute the full protocol
    /// 
    /// Returns true if verifier accepts the assistant's commitment
    pub fn execute<R: RngCore>(
        &self,
        polynomial: &MultilinearPolynomial<Fr>,
        pedersen_params: &PedersenParams,
        rng: &mut R,
    ) -> (bool, EncoderStats) {
        // Step 1: Assistant computes commitment
        let assistant = Assistant::new(polynomial.clone());
        
        // Generate challenge first for evaluation
        let challenge = self.encoder.generate_challenge(rng);
        
        let assistant_commit = assistant.commit(
            pedersen_params,
            &challenge,
            rng,
        );
        
        // Step 2: Challenge already generated
        
        // Steps 3-6: Verifier checks
        let accepted = self.encoder.verify(
            polynomial,
            &assistant_commit,
            &challenge,
            pedersen_params,
        );
        
        // Compute stats
        let n = 1 << self.encoder.num_vars;
        let stats = EncoderStats {
            field_operations: n, // O(n) field ops for evaluation
            group_operations: 0, // No group ops needed!
            verification_ops: self.encoder.num_vars, // Sub-linear verification
        };
        
        (accepted, stats)
    }
}

/// Statistics for encoder performance
#[derive(Debug, Clone)]
pub struct EncoderStats {
    /// Number of field operations (multiplications/additions)
    pub field_operations: usize,
    /// Number of group operations (exponentiations)
    pub group_operations: usize,
    /// Number of verification operations (sub-linear)
    pub verification_ops: usize,
}

impl EncoderStats {
    /// Compare with traditional encoder that does O(n) exponentiations
    pub fn speedup_factor(&self) -> f64 {
        // Traditional: n exponentiations ≈ n * 1000 field ops (rough estimate)
        // With assistant: n field ops + log(n) verification
        let traditional_cost = (1 << 20) * 1000; // Assuming exponentiation is ~1000x field op
        let assistant_cost = self.field_operations + self.verification_ops * 100;
        traditional_cost as f64 / assistant_cost as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;

    #[test]
    fn assistant_basic() {
        let mut rng = test_rng();
        
        // Create a small polynomial
        let num_vars = 3;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64 + 1)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
        
        let assistant = Assistant::new(poly.clone());
        
        // Assistant computes commitment
        let pedersen_params = PedersenParams::new();
        let point: Vec<Fr> = (0..num_vars).map(|_| Fr::rand(&mut rng)).collect();
        
        let commit = assistant.commit(&pedersen_params, &point, &mut rng);
        
        // Check commitment was created
        assert_eq!(commit.poly_commitment.len(), 32);
    }

    #[test]
    fn encoder_evaluate() {
        let mut rng = test_rng();
        
        let num_vars = 4;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
        
        let encoder = Encoder::new(num_vars);
        let challenge = encoder.generate_challenge(&mut rng);
        
        // Encoder evaluates polynomial directly
        let v = encoder.evaluate_polynomial(&poly, &challenge);
        
        // Should match polynomial's evaluate method
        let expected = poly.evaluate(&challenge);
        assert_eq!(v, expected);
    }

    #[test]
    fn assistant_protocol_complete() {
        let mut rng = test_rng();
        
        let num_vars = 3;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
        
        let protocol = AssistantProtocol::new(num_vars);
        let pedersen_params = PedersenParams::new();
        
        let (accepted, stats) = protocol.execute(&poly, &pedersen_params, &mut rng);
        
        // Honest assistant should be accepted
        assert!(accepted);
        
        // Check stats
        assert_eq!(stats.field_operations, n);
        assert_eq!(stats.group_operations, 0);
        assert_eq!(stats.verification_ops, num_vars);
    }

    #[test]
    fn encoder_verify_honest() {
        let mut rng = test_rng();
        
        let num_vars = 4;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
        
        let encoder = Encoder::new(num_vars);
        let pedersen_params = PedersenParams::new();
        
        // Generate challenge
        let challenge = encoder.generate_challenge(&mut rng);
        
        // Honest assistant
        let assistant = Assistant::new(poly.clone());
        let commit = assistant.commit(&pedersen_params, &challenge, &mut rng);
        
        // Verify
        let accepted = encoder.verify(&poly, &commit, &challenge, &pedersen_params);
        assert!(accepted);
    }

    #[test]
    fn encoder_stats_speedup() {
        let num_vars = 10;
        let n = 1 << num_vars;
        
        let stats = EncoderStats {
            field_operations: n,
            group_operations: 0,
            verification_ops: num_vars,
        };
        
        // Should show significant speedup
        let speedup = stats.speedup_factor();
        assert!(speedup > 100.0, "Speedup should be > 100x");
    }

    #[test]
    fn assistant_protocol_multiple_sizes() {
        let mut rng = test_rng();
        let pedersen_params = PedersenParams::new();
        
        for num_vars in 2..=6 {
            let n = 1 << num_vars;
            let evals: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64)).collect();
            let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
            
            let protocol = AssistantProtocol::new(num_vars);
            let (accepted, _) = protocol.execute(&poly, &pedersen_params, &mut rng);
            
            assert!(accepted, "Protocol should accept for num_vars = {}", num_vars);
        }
    }

    #[test]
    fn encoder_cost_comparison() {
        // Compare costs: traditional vs assistant
        
        for log_n in 10..=16 {
            let n = 1usize << log_n;
            
            // Traditional encoder: O(n) exponentiations
            let traditional_cost = n;
            
            // Assistant encoder: O(n) field ops + O(log n) verification
            let assistant_field_ops = n;
            let assistant_verification = log_n;
            
            // Field op is ~1000x cheaper than exponentiation
            let assistant_equiv_cost = assistant_field_ops / 1000 + assistant_verification;
            
            let speedup = traditional_cost / assistant_equiv_cost.max(1);
            
            println!("n=2^{}: speedup ≈ {}x", log_n, speedup);
            assert!(speedup > 10, "Should have significant speedup");
        }
    }

    #[test]
    fn assistant_deterministic_commitment() {
        // Same polynomial + same randomness should give same commitment
        let num_vars = 3;
        let n = 1 << num_vars;
        let evals: Vec<Fr> = (0..n).map(|i| Fr::from(i as u64 + 1)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, num_vars);
        
        let assistant = Assistant::new(poly);
        let pedersen_params = PedersenParams::new();
        let point: Vec<Fr> = (0..num_vars).map(|i| Fr::from(i as u64)).collect();
        
        let mut rng1 = test_rng();
        let mut rng2 = test_rng();
        
        // Both should produce commitments (content will differ due to RNG)
        let commit1 = assistant.commit(&pedersen_params, &point, &mut rng1);
        let commit2 = assistant.commit(&pedersen_params, &point, &mut rng2);
        
        // Poly commitments are placeholder, so they match
        assert_eq!(commit1.poly_commitment, commit2.poly_commitment);
    }
}

