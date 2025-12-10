//! Univariate polynomials for sum-check protocol
//!
//! Supports polynomials of degree d for sum-check over products of MLEs.
//! - d=1: single MLE
//! - d=2: product of 2 MLEs (e.g., A·B)
//! - d=3: product of 3 MLEs (e.g., A·B·C for R1CS)

use ark_ff::Field;
use ark_std::vec::Vec;

/// Univariate polynomial of degree at most 1: f(t) = c0 + c1 * t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnivariateDegree1<F: Field> {
    pub c0: F,
    pub c1: F,
}

impl<F: Field> UnivariateDegree1<F> {
    pub fn evaluate(&self, t: F) -> F {
        self.c0 + self.c1 * t
    }

    /// Returns g(0) + g(1) = c0 + (c0 + c1) = 2*c0 + c1
    /// This is the sum over the Boolean domain {0, 1}
    pub fn sum_over_boolean(&self) -> F {
        self.c0.double() + self.c1
    }
}

/// Univariate polynomial of degree at most 2: f(t) = c0 + c1*t + c2*t²
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnivariateDegree2<F: Field> {
    pub c0: F,
    pub c1: F,
    pub c2: F,
}

impl<F: Field> UnivariateDegree2<F> {
    pub fn new(c0: F, c1: F, c2: F) -> Self {
        Self { c0, c1, c2 }
    }

    pub fn evaluate(&self, t: F) -> F {
        // Horner's method: c0 + t*(c1 + t*c2)
        self.c0 + t * (self.c1 + t * self.c2)
    }

    /// Returns g(0) + g(1)
    /// g(0) = c0
    /// g(1) = c0 + c1 + c2
    /// sum = 2*c0 + c1 + c2
    pub fn sum_over_boolean(&self) -> F {
        self.c0.double() + self.c1 + self.c2
    }

    /// Interpolate from 3 points: (0, y0), (1, y1), (2, y2)
    /// Using Lagrange interpolation for degree-2 polynomial
    pub fn interpolate(y0: F, y1: F, y2: F) -> Self {
        // Lagrange basis polynomials evaluated at 0, 1, 2:
        // L0(t) = (t-1)(t-2)/((0-1)(0-2)) = (t-1)(t-2)/2
        // L1(t) = (t-0)(t-2)/((1-0)(1-2)) = t(t-2)/(-1) = -t(t-2) = 2t - t²
        // L2(t) = (t-0)(t-1)/((2-0)(2-1)) = t(t-1)/2
        //
        // f(t) = y0*L0(t) + y1*L1(t) + y2*L2(t)
        //
        // L0(t) = (t² - 3t + 2)/2
        // L1(t) = -t² + 2t = 2t - t²
        // L2(t) = (t² - t)/2
        //
        // f(t) = y0*(t² - 3t + 2)/2 + y1*(2t - t²) + y2*(t² - t)/2
        //
        // Collecting coefficients:
        // c0 = y0 * 2/2 = y0
        // c1 = y0 * (-3/2) + y1 * 2 + y2 * (-1/2)
        // c2 = y0 * (1/2) + y1 * (-1) + y2 * (1/2)
        
        let two = F::one() + F::one();
        let two_inv = two.inverse().unwrap();
        let three = two + F::one();
        
        let c0 = y0;
        let c1 = y1.double() - (y0 * three + y2) * two_inv;
        let c2 = (y0 - y1.double() + y2) * two_inv;
        
        Self { c0, c1, c2 }
    }
}

/// Univariate polynomial of degree at most 3: f(t) = c0 + c1*t + c2*t² + c3*t³
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnivariateDegree3<F: Field> {
    pub c0: F,
    pub c1: F,
    pub c2: F,
    pub c3: F,
}

impl<F: Field> UnivariateDegree3<F> {
    pub fn new(c0: F, c1: F, c2: F, c3: F) -> Self {
        Self { c0, c1, c2, c3 }
    }

    pub fn evaluate(&self, t: F) -> F {
        // Horner's method: c0 + t*(c1 + t*(c2 + t*c3))
        self.c0 + t * (self.c1 + t * (self.c2 + t * self.c3))
    }

    /// Returns g(0) + g(1)
    /// g(0) = c0
    /// g(1) = c0 + c1 + c2 + c3
    /// sum = 2*c0 + c1 + c2 + c3
    pub fn sum_over_boolean(&self) -> F {
        self.c0.double() + self.c1 + self.c2 + self.c3
    }

    /// Interpolate from 4 points: (0, y0), (1, y1), (2, y2), (3, y3)
    pub fn interpolate(y0: F, y1: F, y2: F, y3: F) -> Self {
        // Using Newton's divided differences for numerical stability
        // f[x0] = y0
        // f[x0,x1] = (y1 - y0) / 1
        // f[x0,x1,x2] = (f[x1,x2] - f[x0,x1]) / 2
        // f[x0,x1,x2,x3] = (f[x1,x2,x3] - f[x0,x1,x2]) / 3
        //
        // Then: f(t) = f[x0] + f[x0,x1]*t + f[x0,x1,x2]*t*(t-1) + f[x0,x1,x2,x3]*t*(t-1)*(t-2)
        
        let two = F::one() + F::one();
        let three = two + F::one();
        
        // First divided differences
        let d01 = y1 - y0;
        let d12 = y2 - y1;
        let d23 = y3 - y2;
        
        // Second divided differences
        let d012 = (d12 - d01) * two.inverse().unwrap();
        let d123 = (d23 - d12) * two.inverse().unwrap();
        
        // Third divided difference
        let d0123 = (d123 - d012) * three.inverse().unwrap();
        
        // Newton form: f(t) = y0 + d01*t + d012*t*(t-1) + d0123*t*(t-1)*(t-2)
        // Expand to standard form:
        // = y0 + d01*t + d012*(t² - t) + d0123*(t³ - 3t² + 2t)
        // = y0 + (d01 - d012 + 2*d0123)*t + (d012 - 3*d0123)*t² + d0123*t³
        
        let c0 = y0;
        let c1 = d01 - d012 + d0123.double();
        let c2 = d012 - d0123 * three;
        let c3 = d0123;
        
        Self { c0, c1, c2, c3 }
    }
}

/// Generic univariate polynomial with arbitrary degree
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnivariatePolynomial<F: Field> {
    /// Coefficients [c0, c1, c2, ...] for c0 + c1*t + c2*t² + ...
    pub coeffs: Vec<F>,
}

impl<F: Field> UnivariatePolynomial<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }

    pub fn degree(&self) -> usize {
        if self.coeffs.is_empty() {
            0
        } else {
            self.coeffs.len() - 1
        }
    }

    pub fn evaluate(&self, t: F) -> F {
        if self.coeffs.is_empty() {
            return F::zero();
        }
        // Horner's method
        let mut result = *self.coeffs.last().unwrap();
        for i in (0..self.coeffs.len() - 1).rev() {
            result = result * t + self.coeffs[i];
        }
        result
    }

    /// Returns g(0) + g(1)
    pub fn sum_over_boolean(&self) -> F {
        let g0 = self.evaluate(F::zero());
        let g1 = self.evaluate(F::one());
        g0 + g1
    }

    /// Lagrange interpolation from points (0, 1, 2, ..., d) -> (y0, y1, ..., yd)
    pub fn interpolate(ys: &[F]) -> Self {
        let n = ys.len();
        if n == 0 {
            return Self::new(vec![]);
        }
        if n == 1 {
            return Self::new(vec![ys[0]]);
        }

        // Build Lagrange basis polynomials and sum
        let mut coeffs = vec![F::zero(); n];
        
        for i in 0..n {
            // Compute L_i(t) = Π_{j≠i} (t - j) / (i - j)
            let mut basis_coeffs = vec![F::one()];
            let mut denom = F::one();
            
            for j in 0..n {
                if i != j {
                    let j_f = F::from(j as u64);
                    let i_f = F::from(i as u64);
                    denom *= i_f - j_f;
                    
                    // Multiply by (t - j)
                    let mut new_coeffs = vec![F::zero(); basis_coeffs.len() + 1];
                    for (k, &c) in basis_coeffs.iter().enumerate() {
                        new_coeffs[k] -= c * j_f;
                        new_coeffs[k + 1] += c;
                    }
                    basis_coeffs = new_coeffs;
                }
            }
            
            // Scale by y_i / denom
            let scale = ys[i] * denom.inverse().unwrap();
            for (k, c) in basis_coeffs.iter().enumerate() {
                coeffs[k] += *c * scale;
            }
        }
        
        Self::new(coeffs)
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
    fn degree1_sum_over_boolean() {
        // g(t) = 3 + 5t
        // g(0) = 3, g(1) = 8
        // sum = 11 = 2*3 + 5
        let g = UnivariateDegree1 {
            c0: Fr::from(3u64),
            c1: Fr::from(5u64),
        };
        assert_eq!(g.sum_over_boolean(), Fr::from(11u64));
        assert_eq!(g.evaluate(Fr::zero()) + g.evaluate(Fr::one()), Fr::from(11u64));
    }

    #[test]
    fn degree2_evaluation() {
        // g(t) = 1 + 2t + 3t²
        // g(0) = 1, g(1) = 6, g(2) = 1 + 4 + 12 = 17
        let g = UnivariateDegree2::new(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        assert_eq!(g.evaluate(Fr::zero()), Fr::from(1u64));
        assert_eq!(g.evaluate(Fr::one()), Fr::from(6u64));
        assert_eq!(g.evaluate(Fr::from(2u64)), Fr::from(17u64));
    }

    #[test]
    fn degree2_sum_over_boolean() {
        // g(t) = 1 + 2t + 3t²
        // g(0) = 1, g(1) = 6
        // sum = 7 = 2*1 + 2 + 3
        let g = UnivariateDegree2::new(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        assert_eq!(g.sum_over_boolean(), Fr::from(7u64));
        assert_eq!(g.evaluate(Fr::zero()) + g.evaluate(Fr::one()), Fr::from(7u64));
    }

    #[test]
    fn degree2_interpolation() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let y0 = Fr::from(rng.gen::<u64>() % 1000);
            let y1 = Fr::from(rng.gen::<u64>() % 1000);
            let y2 = Fr::from(rng.gen::<u64>() % 1000);
            
            let g = UnivariateDegree2::interpolate(y0, y1, y2);
            
            assert_eq!(g.evaluate(Fr::zero()), y0, "interpolation failed at t=0");
            assert_eq!(g.evaluate(Fr::one()), y1, "interpolation failed at t=1");
            assert_eq!(g.evaluate(Fr::from(2u64)), y2, "interpolation failed at t=2");
        }
    }

    #[test]
    fn degree3_evaluation() {
        // g(t) = 1 + 2t + 3t² + 4t³
        // g(0) = 1
        // g(1) = 1 + 2 + 3 + 4 = 10
        // g(2) = 1 + 4 + 12 + 32 = 49
        let g = UnivariateDegree3::new(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        assert_eq!(g.evaluate(Fr::zero()), Fr::from(1u64));
        assert_eq!(g.evaluate(Fr::one()), Fr::from(10u64));
        assert_eq!(g.evaluate(Fr::from(2u64)), Fr::from(49u64));
    }

    #[test]
    fn degree3_sum_over_boolean() {
        // g(t) = 1 + 2t + 3t² + 4t³
        // g(0) = 1, g(1) = 10
        // sum = 11 = 2*1 + 2 + 3 + 4
        let g = UnivariateDegree3::new(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        assert_eq!(g.sum_over_boolean(), Fr::from(11u64));
        assert_eq!(g.evaluate(Fr::zero()) + g.evaluate(Fr::one()), Fr::from(11u64));
    }

    #[test]
    fn degree3_interpolation() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let y0 = Fr::from(rng.gen::<u64>() % 1000);
            let y1 = Fr::from(rng.gen::<u64>() % 1000);
            let y2 = Fr::from(rng.gen::<u64>() % 1000);
            let y3 = Fr::from(rng.gen::<u64>() % 1000);
            
            let g = UnivariateDegree3::interpolate(y0, y1, y2, y3);
            
            assert_eq!(g.evaluate(Fr::zero()), y0, "interpolation failed at t=0");
            assert_eq!(g.evaluate(Fr::one()), y1, "interpolation failed at t=1");
            assert_eq!(g.evaluate(Fr::from(2u64)), y2, "interpolation failed at t=2");
            assert_eq!(g.evaluate(Fr::from(3u64)), y3, "interpolation failed at t=3");
        }
    }

    #[test]
    fn generic_polynomial_interpolation() {
        let mut rng = test_rng();
        
        // Test degree 2
        let ys: Vec<Fr> = (0..3).map(|_| Fr::from(rng.gen::<u64>() % 1000)).collect();
        let g = UnivariatePolynomial::interpolate(&ys);
        for (i, &y) in ys.iter().enumerate() {
            assert_eq!(g.evaluate(Fr::from(i as u64)), y);
        }
        
        // Test degree 4
        let ys: Vec<Fr> = (0..5).map(|_| Fr::from(rng.gen::<u64>() % 1000)).collect();
        let g = UnivariatePolynomial::interpolate(&ys);
        for (i, &y) in ys.iter().enumerate() {
            assert_eq!(g.evaluate(Fr::from(i as u64)), y);
        }
    }

    #[test]
    fn generic_polynomial_sum_over_boolean() {
        // Same as degree2 test
        let g = UnivariatePolynomial::new(vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ]);
        assert_eq!(g.sum_over_boolean(), Fr::from(7u64));
    }

    #[test]
    fn degree2_from_product_of_two_mles() {
        // If we have two MLEs f(x) and g(x), each linear in the current variable,
        // their product f(t)*g(t) is degree 2.
        // f(t) = a0 + a1*t, g(t) = b0 + b1*t
        // Product = a0*b0 + (a0*b1 + a1*b0)*t + a1*b1*t²
        
        let a0 = Fr::from(3u64);
        let a1 = Fr::from(5u64);
        let b0 = Fr::from(2u64);
        let b1 = Fr::from(7u64);
        
        // Compute product coefficients
        let c0 = a0 * b0;           // 6
        let c1 = a0 * b1 + a1 * b0; // 21 + 10 = 31
        let c2 = a1 * b1;           // 35
        
        let product = UnivariateDegree2::new(c0, c1, c2);
        
        // Verify at several points
        for t in 0..5u64 {
            let t_f = Fr::from(t);
            let f_t = a0 + a1 * t_f;
            let g_t = b0 + b1 * t_f;
            let expected = f_t * g_t;
            assert_eq!(product.evaluate(t_f), expected);
        }
    }

    #[test]
    fn degree3_from_product_of_three_mles() {
        // f(t)*g(t)*h(t) where each is linear gives degree 3
        let a0 = Fr::from(2u64);
        let a1 = Fr::from(3u64);
        let b0 = Fr::from(1u64);
        let b1 = Fr::from(4u64);
        let c0 = Fr::from(5u64);
        let c1 = Fr::from(2u64);
        
        // Compute values at t = 0, 1, 2, 3 and interpolate
        let mut ys = Vec::new();
        for t in 0..4u64 {
            let t_f = Fr::from(t);
            let f_t = a0 + a1 * t_f;
            let g_t = b0 + b1 * t_f;
            let h_t = c0 + c1 * t_f;
            ys.push(f_t * g_t * h_t);
        }
        
        let product = UnivariateDegree3::interpolate(ys[0], ys[1], ys[2], ys[3]);
        
        // Verify at more points
        for t in 0..10u64 {
            let t_f = Fr::from(t);
            let f_t = a0 + a1 * t_f;
            let g_t = b0 + b1 * t_f;
            let h_t = c0 + c1 * t_f;
            let expected = f_t * g_t * h_t;
            assert_eq!(product.evaluate(t_f), expected, "mismatch at t={}", t);
        }
    }
}
