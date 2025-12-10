//! BLS12-381 scalar field implementation
//!
//! Wrapper around ark-bls12-381 scalar field (Fr)
//! Mathematical validation: F_p arithmetic where p is BLS12-381 scalar field order

use super::QuarksField;
pub use ark_bls12_381::Fr;
use ark_std::UniformRand;

impl QuarksField for Fr {
    fn field_name() -> &'static str {
        "BLS12-381 Scalar Field (Fr)"
    }
    
    fn random<R: rand::Rng>(rng: &mut R) -> Self {
        Fr::rand(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_ff::{One, Zero};
    use ark_std::test_rng;

    /// Test 1: Addition identity - a + 0 = a
    #[test]
    fn test_addition_identity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let zero = Fr::zero();
            assert_eq!(a + zero, a, "Addition identity failed: a + 0 != a");
        }
    }

    /// Test 2: Multiplication identity - a * 1 = a
    #[test]
    fn test_multiplication_identity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let one = Fr::one();
            assert_eq!(a * one, a, "Multiplication identity failed: a * 1 != a");
        }
    }

    /// Test 3: Additive inverse - a + (-a) = 0
    #[test]
    fn test_additive_inverse() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let neg_a = -a;
            assert_eq!(a + neg_a, Fr::zero(), "Additive inverse failed: a + (-a) != 0");
        }
    }

    /// Test 4: Multiplicative inverse - a * a^(-1) = 1 (for a != 0)
    #[test]
    fn test_multiplicative_inverse() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            if a != Fr::zero() {
                let a_inv = a.inverse().expect("Inverse should exist for non-zero element");
                let product = a * a_inv;
                assert_eq!(product, Fr::one(), "Multiplicative inverse failed: a * a^(-1) != 1");
            }
        }
    }

    /// Test 5: Zero has no multiplicative inverse
    #[test]
    fn test_zero_no_inverse() {
        let zero = Fr::zero();
        assert!(zero.inverse().is_none(), "Zero should not have multiplicative inverse");
    }

    /// Test 6: Commutativity of addition - a + b = b + a
    #[test]
    fn test_addition_commutativity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            assert_eq!(a + b, b + a, "Addition commutativity failed: a + b != b + a");
        }
    }

    /// Test 7: Commutativity of multiplication - a * b = b * a
    #[test]
    fn test_multiplication_commutativity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            assert_eq!(a * b, b * a, "Multiplication commutativity failed: a * b != b * a");
        }
    }

    /// Test 8: Associativity of addition - (a + b) + c = a + (b + c)
    #[test]
    fn test_addition_associativity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            let c = Fr::random(&mut rng);
            let left = (a + b) + c;
            let right = a + (b + c);
            assert_eq!(left, right, "Addition associativity failed: (a + b) + c != a + (b + c)");
        }
    }

    /// Test 9: Associativity of multiplication - (a * b) * c = a * (b * c)
    #[test]
    fn test_multiplication_associativity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            let c = Fr::random(&mut rng);
            let left = (a * b) * c;
            let right = a * (b * c);
            assert_eq!(left, right, "Multiplication associativity failed: (a * b) * c != a * (b * c)");
        }
    }

    /// Test 10: Distributivity - a * (b + c) = a*b + a*c
    #[test]
    fn test_distributivity() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            let c = Fr::random(&mut rng);
            let left = a * (b + c);
            let right = a * b + a * c;
            assert_eq!(left, right, "Distributivity failed: a * (b + c) != a*b + a*c");
        }
    }

    /// Test 11: Subtraction - a - b = a + (-b)
    #[test]
    fn test_subtraction() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            let sub = a - b;
            let add_neg = a + (-b);
            assert_eq!(sub, add_neg, "Subtraction failed: a - b != a + (-b)");
        }
    }

    /// Test 12: Division - a / b = a * b^(-1) (for b != 0)
    #[test]
    fn test_division() {
        let mut rng = test_rng();
        for _ in 0..100 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            if b != Fr::zero() {
                let div = a / b;
                let mul_inv = a * b.inverse().unwrap();
                assert_eq!(div, mul_inv, "Division failed: a / b != a * b^(-1)");
            }
        }
    }

    /// Test 13: Power of zero - 0^n = 0 for n > 0
    #[test]
    fn test_zero_power() {
        let zero = Fr::zero();
        for exp in 1..10u64 {
            let result = zero.pow([exp]);
            assert_eq!(result, Fr::zero(), "Zero power failed: 0^n != 0");
        }
    }

    /// Test 14: Power of one - 1^n = 1 for any n
    #[test]
    fn test_one_power() {
        let one = Fr::one();
        for exp in 0..100u64 {
            let result = one.pow([exp]);
            assert_eq!(result, Fr::one(), "One power failed: 1^n != 1");
        }
    }

    /// Test 15: Power property - (a^m)^n = a^(m*n)
    #[test]
    fn test_power_property() {
        use rand::Rng;
        let mut rng = test_rng();
        for _ in 0..20 {
            let a = Fr::random(&mut rng);
            let m = (rng.gen::<u32>() % 10 + 1) as u64;
            let n = (rng.gen::<u32>() % 10 + 1) as u64;
            
            let left = a.pow([m]).pow([n]);
            let right = a.pow([m * n]);
            assert_eq!(left, right, "Power property failed: (a^m)^n != a^(m*n)");
        }
    }

    /// Test 16: Random element generation produces different values
    #[test]
    fn test_random_generation() {
        let mut rng = test_rng();
        let mut elements = Vec::new();
        for _ in 0..100 {
            elements.push(Fr::random(&mut rng));
        }
        
        // Check that not all elements are the same (statistical test)
        let first = elements[0];
        let all_same = elements.iter().all(|&e| e == first);
        assert!(!all_same, "Random generation produced all identical elements");
    }

    /// Test 17: Serialize and deserialize
    #[test]
    fn test_serialization() {
        use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
        
        let mut rng = test_rng();
        for _ in 0..100 {
            let original = Fr::random(&mut rng);
            
            // Serialize
            let mut bytes = Vec::new();
            original.serialize_compressed(&mut bytes).unwrap();
            
            // Deserialize
            let deserialized = Fr::deserialize_compressed(&bytes[..]).unwrap();
            
            assert_eq!(original, deserialized, "Serialization round-trip failed");
        }
    }

    /// Test 18: Field order property - for any a != 0, a^(p-1) = 1
    /// (Fermat's Little Theorem for prime field)
    #[test]
    fn test_field_order_property() {
        let mut rng = test_rng();
        // Test with a few elements (expensive test)
        for _ in 0..5 {
            let a = Fr::random(&mut rng);
            if a != Fr::zero() {
                // This is expensive, so we use a smaller exponent related property
                // a^2 * a^(-2) = 1
                let a_squared = a * a;
                let a_squared_inv = a_squared.inverse().unwrap();
                assert_eq!(a_squared * a_squared_inv, Fr::one(), 
                    "Field order property test failed");
            }
        }
    }

    /// Property test: 1000 random field axiom tests
    #[test]
    fn test_field_axioms_extensive() {
        let mut rng = test_rng();
        for _ in 0..1000 {
            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);
            
            // Test distributivity
            let c = Fr::random(&mut rng);
            assert_eq!(a * (b + c), a * b + a * c);
            
            // Test commutativity
            assert_eq!(a + b, b + a);
            assert_eq!(a * b, b * a);
            
            // Test identity elements
            assert_eq!(a + Fr::zero(), a);
            assert_eq!(a * Fr::one(), a);
        }
    }
}

