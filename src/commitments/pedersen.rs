//! Pedersen Commitment Scheme
//!
//! C = x·G + r·H where:
//! - G, H are independent generators (nothing-up-my-sleeve)
//! - x is the committed value (scalar)
//! - r is the blinding factor (random scalar)
//!
//! Properties:
//! - **Binding**: Cannot open to two different values (computational, relies on DL)
//! - **Hiding**: C reveals no information about x (perfect hiding)
//! - **Homomorphic**: C(x) + C(y) = C(x+y) with combined blinding

use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{PrimeGroup, AdditiveGroup};
use ark_ff::UniformRand;
use ark_std::rand::RngCore;
use crate::utils::msm::msm;

/// Public parameters for Pedersen commitments
#[derive(Clone, Debug)]
pub struct PedersenParams {
    /// Generator G (base point)
    pub g: G1Projective,
    /// Generator H (for blinding)
    pub h: G1Projective,
}

impl PedersenParams {
    /// Setup with default generators derived from the curve generator
    /// In production, H should be derived via hash-to-curve for security
    pub fn new() -> Self {
        // Use the standard generator for G
        let g = G1Projective::generator();
        
        // Derive H by scalar multiplication with a "random" scalar
        // In production, use hash_to_curve with domain separator
        // This is NOT secure - H should be independently generated
        let h_scalar = Fr::from(9u64); // Placeholder
        let h = g * h_scalar;
        
        Self { g, h }
    }

    /// Setup with explicit generators (for testing or custom setup)
    pub fn with_generators(g: G1Projective, h: G1Projective) -> Self {
        Self { g, h }
    }

    /// Commit to a scalar value with random blinding
    pub fn commit<R: RngCore>(&self, value: &Fr, rng: &mut R) -> PedersenCommitment {
        let blinding = Fr::rand(rng);
        self.commit_with_blinding(value, &blinding)
    }

    /// Commit with explicit blinding factor
    pub fn commit_with_blinding(&self, value: &Fr, blinding: &Fr) -> PedersenCommitment {
        // C = value·G + blinding·H
        let commitment = self.g * value + self.h * blinding;
        PedersenCommitment {
            point: commitment,
            blinding: *blinding,
        }
    }

    /// Verify that a commitment opens to the claimed value
    pub fn verify(&self, commitment: &G1Projective, value: &Fr, blinding: &Fr) -> bool {
        let expected = self.g * value + self.h * blinding;
        *commitment == expected
    }

    /// Commit to a vector of scalars: C = Σ v_i·G_i + r·H
    /// Uses powers of G: G_i = G^(2^i) for simplicity
    pub fn commit_vector<R: RngCore>(&self, values: &[Fr], rng: &mut R) -> VectorCommitment {
        let blinding = Fr::rand(rng);
        self.commit_vector_with_blinding(values, &blinding)
    }

    /// Commit to vector with explicit blinding
    /// Uses Pippenger's MSM for O(n/log n) complexity
    pub fn commit_vector_with_blinding(&self, values: &[Fr], blinding: &Fr) -> VectorCommitment {
        // Generate generators: G_i = G * 2^i
        let generators: Vec<G1Projective> = (0..values.len())
            .map(|i| {
                let mut gen = self.g;
                for _ in 0..i {
                    gen = gen.double();
                }
                gen
            })
            .collect();
        
        // MSM: Σ v_i * G_i using Pippenger's algorithm
        let value_commitment = msm(&generators, values);
        
        // Add blinding: C = Σ v_i·G_i + r·H
        let point = value_commitment + self.h * blinding;
        
        VectorCommitment {
            point,
            blinding: *blinding,
        }
    }
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

/// A Pedersen commitment with its opening hint (blinding factor)
#[derive(Clone, Debug)]
pub struct PedersenCommitment {
    /// The commitment point C = x·G + r·H
    pub point: G1Projective,
    /// The blinding factor r (secret)
    pub blinding: Fr,
}

impl PedersenCommitment {
    /// Get just the commitment point (for public use)
    pub fn point(&self) -> G1Projective {
        self.point
    }

    /// Homomorphic addition of commitments
    /// C(x) + C(y) = C(x+y) with blinding r1 + r2
    pub fn add(&self, other: &PedersenCommitment) -> PedersenCommitment {
        PedersenCommitment {
            point: self.point + other.point,
            blinding: self.blinding + other.blinding,
        }
    }

    /// Scalar multiplication of commitment
    /// s·C(x) = C(s·x) with blinding s·r
    pub fn scale(&self, scalar: &Fr) -> PedersenCommitment {
        PedersenCommitment {
            point: self.point * scalar,
            blinding: self.blinding * scalar,
        }
    }
}

/// A commitment to a vector of scalars
#[derive(Clone, Debug)]
pub struct VectorCommitment {
    pub point: G1Projective,
    pub blinding: Fr,
}

impl VectorCommitment {
    pub fn point(&self) -> G1Projective {
        self.point
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::Zero;

    #[test]
    fn pedersen_commit_and_verify() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        for _ in 0..50 {
            let value = Fr::rand(&mut rng);
            let commitment = params.commit(&value, &mut rng);
            
            assert!(
                params.verify(&commitment.point, &value, &commitment.blinding),
                "commitment should verify"
            );
        }
    }

    #[test]
    fn pedersen_binding() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let value1 = Fr::rand(&mut rng);
        let commitment = params.commit(&value1, &mut rng);

        // Try to open to a different value - should fail
        for _ in 0..100 {
            let value2 = Fr::rand(&mut rng);
            if value2 == value1 {
                continue;
            }
            let fake_blinding = Fr::rand(&mut rng);
            
            assert!(
                !params.verify(&commitment.point, &value2, &fake_blinding),
                "should not open to different value"
            );
        }
    }

    #[test]
    fn pedersen_hiding() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let value = Fr::rand(&mut rng);
        let c1 = params.commit(&value, &mut rng);
        let c2 = params.commit(&value, &mut rng);

        // Different blinding → different commitment
        assert_ne!(
            c1.point, c2.point,
            "same value with different blinding should give different commitments"
        );

        // Both should still verify
        assert!(params.verify(&c1.point, &value, &c1.blinding));
        assert!(params.verify(&c2.point, &value, &c2.blinding));
    }

    #[test]
    fn pedersen_homomorphic_addition() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        for _ in 0..50 {
            let x = Fr::rand(&mut rng);
            let y = Fr::rand(&mut rng);

            let cx = params.commit(&x, &mut rng);
            let cy = params.commit(&y, &mut rng);

            // C(x) + C(y) should equal C(x+y)
            let c_sum = cx.add(&cy);
            let sum = x + y;

            assert!(
                params.verify(&c_sum.point, &sum, &c_sum.blinding),
                "homomorphic addition should work"
            );
        }
    }

    #[test]
    fn pedersen_homomorphic_scalar_mult() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        for _ in 0..50 {
            let x = Fr::rand(&mut rng);
            let s = Fr::rand(&mut rng);

            let cx = params.commit(&x, &mut rng);
            
            // s·C(x) should equal C(s·x)
            let c_scaled = cx.scale(&s);
            let scaled = x * s;

            assert!(
                params.verify(&c_scaled.point, &scaled, &c_scaled.blinding),
                "homomorphic scalar multiplication should work"
            );
        }
    }

    #[test]
    fn pedersen_zero_blinding() {
        let params = PedersenParams::new();
        let value = Fr::from(42u64);
        let zero = Fr::zero();

        let commitment = params.commit_with_blinding(&value, &zero);
        
        // C = 42·G + 0·H = 42·G
        let expected = params.g * value;
        assert_eq!(commitment.point, expected);
    }

    #[test]
    fn pedersen_vector_commitment() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let values: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let commitment = params.commit_vector(&values, &mut rng);

        // Verify by recomputing
        let recomputed = params.commit_vector_with_blinding(&values, &commitment.blinding);
        assert_eq!(commitment.point, recomputed.point);
    }

    #[test]
    fn pedersen_deterministic_with_same_blinding() {
        let params = PedersenParams::new();
        let value = Fr::from(123u64);
        let blinding = Fr::from(456u64);

        let c1 = params.commit_with_blinding(&value, &blinding);
        let c2 = params.commit_with_blinding(&value, &blinding);

        assert_eq!(c1.point, c2.point);
    }

    #[test]
    fn pedersen_linearity() {
        let params = PedersenParams::new();
        let mut rng = test_rng();

        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let rx = Fr::rand(&mut rng);
        let ry = Fr::rand(&mut rng);

        let cx = params.commit_with_blinding(&x, &rx);
        let cy = params.commit_with_blinding(&y, &ry);

        // LHS: a·C(x) + b·C(y)
        let lhs = cx.scale(&a).add(&cy.scale(&b));

        // RHS: C(ax + by) with blinding a·rx + b·ry
        let combined_value = a * x + b * y;
        let combined_blinding = a * rx + b * ry;
        let rhs = params.commit_with_blinding(&combined_value, &combined_blinding);

        assert_eq!(lhs.point, rhs.point, "linearity should hold");
    }
}
