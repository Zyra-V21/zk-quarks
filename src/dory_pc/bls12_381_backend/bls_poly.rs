//! Polynomial implementation for BLS12-381

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use super::bls_field::Bls381Fr;
use crate::dory_pc::{DoryError, ProverSetup};
use crate::dory_pc::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::dory_pc::primitives::poly::{MultilinearLagrange, Polynomial};

/// Compute multilinear Lagrange basis at a point
/// output[i] = Π_j ((1 - x_j)(1 - b_ij) + x_j·b_ij)
/// where b_ij is the j-th bit of i
fn multilinear_lagrange_basis(output: &mut [Bls381Fr], point: &[Bls381Fr]) {
    let n = output.len();
    let num_vars = point.len();
    assert_eq!(1 << num_vars, n, "Output size mismatch");

    for (i, out) in output.iter_mut().enumerate() {
        let mut basis_i = Bls381Fr::one();
        for (j, x_j) in point.iter().enumerate() {
            let bit_j = ((i >> j) & 1) == 1;
            if bit_j {
                basis_i = basis_i.mul(x_j);
            } else {
                basis_i = basis_i.mul(&(Bls381Fr::one() - *x_j));
            }
        }
        *out = basis_i;
    }
}

/// Polynomial implementation wrapping coefficient vector
#[derive(Clone, Debug)]
pub struct Bls381Polynomial {
    coefficients: Vec<Bls381Fr>,
    num_vars: usize,
}

impl Bls381Polynomial {
    pub fn new(coefficients: Vec<Bls381Fr>) -> Self {
        let len = coefficients.len();
        let num_vars = (len as f64).log2() as usize;
        assert_eq!(
            1 << num_vars,
            len,
            "Coefficient length must be a power of 2"
        );
        Self {
            coefficients,
            num_vars,
        }
    }
}

impl Polynomial<Bls381Fr> for Bls381Polynomial {
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    #[tracing::instrument(skip_all, name = "Bls381Polynomial::evaluate", fields(num_vars = self.num_vars))]
    fn evaluate(&self, point: &[Bls381Fr]) -> Bls381Fr {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");

        // Compute multilinear Lagrange basis
        let mut basis = vec![Bls381Fr::zero(); 1 << self.num_vars];
        multilinear_lagrange_basis(&mut basis, point);

        // Evaluate: sum_i coeff[i] * basis[i]
        let mut result = Bls381Fr::zero();
        for (coeff, basis_val) in self.coefficients.iter().zip(basis.iter()) {
            result = result + coeff.mul(basis_val);
        }
        result
    }

    #[tracing::instrument(skip_all, name = "Bls381Polynomial::commit", fields(nu, sigma, num_rows = 1 << nu, num_cols = 1 << sigma))]
    fn commit<E, M1>(
        &self,
        nu: usize,
        sigma: usize,
        setup: &ProverSetup<E>,
    ) -> Result<(E::GT, Vec<E::G1>), DoryError>
    where
        E: PairingCurve,
        M1: DoryRoutines<E::G1>,
        E::G1: Group<Scalar = Bls381Fr>,
    {
        let expected_len = 1 << (nu + sigma);
        if self.coefficients.len() != expected_len {
            return Err(DoryError::InvalidSize {
                expected: expected_len,
                actual: self.coefficients.len(),
            });
        }

        let num_rows = 1 << nu;
        let num_cols = 1 << sigma;

        // Tier 1: Compute row commitments
        let mut row_commitments = Vec::with_capacity(num_rows);
        for i in 0..num_rows {
            let row_start = i * num_cols;
            let row_end = row_start + num_cols;
            let row = &self.coefficients[row_start..row_end];

            let g1_bases = &setup.g1_vec[..num_cols];
            let row_commit = M1::msm(g1_bases, row);
            row_commitments.push(row_commit);
        }

        // Tier 2: Compute final commitment via multi-pairing (g2_bases from setup)
        let g2_bases = &setup.g2_vec[..num_rows];
        let commitment = E::multi_pair_g2_setup(&row_commitments, g2_bases);

        Ok((commitment, row_commitments))
    }
}

impl MultilinearLagrange<Bls381Fr> for Bls381Polynomial {
    #[tracing::instrument(skip_all, name = "Bls381Polynomial::vector_matrix_product", fields(nu, sigma, num_rows = 1 << nu, num_cols = 1 << sigma))]
    fn vector_matrix_product(&self, left_vec: &[Bls381Fr], nu: usize, sigma: usize) -> Vec<Bls381Fr> {
        let num_cols = 1 << sigma;
        let num_rows = 1 << nu;
        let mut v_vec = vec![Bls381Fr::zero(); num_cols];

        for (j, v) in v_vec.iter_mut().enumerate() {
            let mut sum = Bls381Fr::zero();
            for (i, left_val) in left_vec.iter().enumerate().take(num_rows) {
                let coeff_idx = i * num_cols + j;
                if coeff_idx < self.coefficients.len() {
                    sum = sum + left_val.mul(&self.coefficients[coeff_idx]);
                }
            }
            *v = sum;
        }

        v_vec
    }
}

