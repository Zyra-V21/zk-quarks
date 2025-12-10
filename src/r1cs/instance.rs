//! R1CS instance and verifier
//!
//! Checks: (A·z) ◦ (B·z) = (C·z) where z = (io, 1, w)

use super::SparseMatrix;
use super::Witness;
use ark_ff::Field;
use crate::errors::{QuarksError, Result};

#[derive(Debug, Clone)]
pub struct R1CSInstance<F: Field> {
    pub a: SparseMatrix<F>,
    pub b: SparseMatrix<F>,
    pub c: SparseMatrix<F>,
    pub num_constraints: usize,
    pub num_vars: usize,   // total vars including io + witness + 1
    pub num_inputs: usize, // |io|
}

impl<F: Field> R1CSInstance<F> {
    pub fn new(
        a: SparseMatrix<F>,
        b: SparseMatrix<F>,
        c: SparseMatrix<F>,
        num_constraints: usize,
        num_vars: usize,
        num_inputs: usize,
    ) -> Self {
        Self {
            a,
            b,
            c,
            num_constraints,
            num_vars,
            num_inputs,
        }
    }

    /// Verify R1CS satisfaction for given witness/public inputs
    pub fn is_satisfied(&self, witness: &Witness<F>) -> Result<bool> {
        // Check sizes
        if witness.num_inputs() != self.num_inputs {
            return Err(QuarksError::InvalidParameter(format!(
                "public inputs mismatch: expected {}, got {}",
                self.num_inputs,
                witness.num_inputs()
            )));
        }

        let total_vars = self.num_inputs + 1 + witness.num_witness();
        if total_vars != self.num_vars {
            return Err(QuarksError::InvalidParameter(format!(
                "variable count mismatch: expected {}, got {}",
                self.num_vars, total_vars
            )));
        }

        let z = witness.build_z(); // (io, 1, w)

        // Compute A·z, B·z, C·z
        let az = self.a.mul_vector(&z);
        let bz = self.b.mul_vector(&z);
        let cz = self.c.mul_vector(&z);

        if az.len() != self.num_constraints
            || bz.len() != self.num_constraints
            || cz.len() != self.num_constraints
        {
            return Err(QuarksError::InvalidParameter(
                "matrix row count mismatch with num_constraints".to_string(),
            ));
        }

        // Check Hadamard equality
        for i in 0..self.num_constraints {
            if az[i] * bz[i] != cz[i] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use ark_ff::One;

    fn instance_mul_gate() -> (R1CSInstance<Fr>, Witness<Fr>) {
        // Constraint: x * y = z
        // z = (1, x, y, z)
        // num_inputs = 0, num_vars = 4 (1 constant + 3 witness vars)
        let num_inputs = 0;
        let num_vars = 4;
        let num_constraints = 1;

        // Row 0 of A: select x
        let mut a = SparseMatrix::new(num_constraints, num_vars);
        a.add_entry(0, 1, Fr::one()); // x at index 1 (after constant)

        // Row 0 of B: select y
        let mut b = SparseMatrix::new(num_constraints, num_vars);
        b.add_entry(0, 2, Fr::one()); // y at index 2

        // Row 0 of C: select z
        let mut c = SparseMatrix::new(num_constraints, num_vars);
        c.add_entry(0, 3, Fr::one()); // z at index 3

        let instance = R1CSInstance::new(a, b, c, num_constraints, num_vars, num_inputs);

        // Witness: x=3, y=4, z=12
        let wit = Witness {
            public_inputs: vec![],
            assignments: vec![Fr::from(3u64), Fr::from(4u64), Fr::from(12u64)],
        };
        (instance, wit)
    }

    fn instance_add_gate() -> (R1CSInstance<Fr>, Witness<Fr>) {
        // Constraint: x + y = z  encoded as (x + y) * 1 = z
        let num_inputs = 0;
        let num_vars = 4;
        let num_constraints = 1;

        let mut a = SparseMatrix::new(num_constraints, num_vars);
        a.add_entry(0, 1, Fr::one()); // x
        a.add_entry(0, 2, Fr::one()); // y

        let mut b = SparseMatrix::new(num_constraints, num_vars);
        b.add_entry(0, 0, Fr::one()); // constant 1 at position 0 (io len=0 so const index=0)

        let mut c = SparseMatrix::new(num_constraints, num_vars);
        c.add_entry(0, 3, Fr::one()); // z

        let instance = R1CSInstance::new(a, b, c, num_constraints, num_vars, num_inputs);

        // Witness: x=5, y=7, z=12
        let wit = Witness {
            public_inputs: vec![],
            assignments: vec![Fr::from(5u64), Fr::from(7u64), Fr::from(12u64)],
        };
        (instance, wit)
    }

    #[test]
    fn test_mul_gate_satisfied() {
        let (inst, wit) = instance_mul_gate();
        assert!(inst.is_satisfied(&wit).unwrap());
    }

    #[test]
    fn test_mul_gate_unsatisfied() {
        let (inst, mut wit) = instance_mul_gate();
        wit.assignments[2] = Fr::from(15u64); // wrong z
        assert!(!inst.is_satisfied(&wit).unwrap());
    }

    #[test]
    fn test_add_gate_satisfied() {
        let (inst, wit) = instance_add_gate();
        assert!(inst.is_satisfied(&wit).unwrap());
    }

    #[test]
    fn test_add_gate_unsatisfied() {
        let (inst, mut wit) = instance_add_gate();
        wit.assignments[2] = Fr::from(20u64); // wrong z
        assert!(!inst.is_satisfied(&wit).unwrap());
    }

    #[test]
    fn test_size_mismatch_inputs() {
        let (inst, mut wit) = instance_mul_gate();
        wit.public_inputs = vec![Fr::one()]; // mismatch
        let res = inst.is_satisfied(&wit);
        assert!(res.is_err());
    }

    #[test]
    fn test_size_mismatch_vars() {
        let (mut inst, wit) = instance_mul_gate();
        inst.num_vars = 5; // wrong
        let res = inst.is_satisfied(&wit);
        assert!(res.is_err());
    }
}

