//! Sparse matrix representation and basic operations
//!
//! Stored as a list of (row, col, value) triples in row-major form.

use ark_ff::Field;
use rayon::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SparseMatrix<F: Field> {
    pub num_rows: usize,
    pub num_cols: usize,
    pub entries: Vec<(usize, usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            num_rows,
            num_cols,
            entries: Vec::new(),
        }
    }

    /// Add an entry (row, col, value). Panics if out of bounds.
    pub fn add_entry(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.num_rows, "row out of bounds");
        assert!(col < self.num_cols, "col out of bounds");
        self.entries.push((row, col, value));
    }

    /// Matrix-vector product: returns a vector of length num_rows
    /// Uses parallel evaluation for large matrices
    pub fn mul_vector(&self, vector: &[F]) -> Vec<F> {
        assert_eq!(vector.len(), self.num_cols, "vector length mismatch");
        
        const PARALLEL_THRESHOLD: usize = 1000; // Parallelize if ≥1000 entries
        
        if self.entries.len() >= PARALLEL_THRESHOLD {
            self.mul_vector_parallel(vector)
        } else {
            self.mul_vector_sequential(vector)
        }
    }
    
    /// Sequential matrix-vector product (for small matrices)
    fn mul_vector_sequential(&self, vector: &[F]) -> Vec<F> {
        let mut result = vec![F::zero(); self.num_rows];
        for &(r, c, ref v) in &self.entries {
            result[r] += *v * vector[c];
        }
        result
    }
    
    /// Parallel matrix-vector product (for large matrices)
    /// Groups entries by row and processes rows in parallel
    fn mul_vector_parallel(&self, vector: &[F]) -> Vec<F> {
        // Group entries by row
        let mut rows_map: HashMap<usize, Vec<(usize, F)>> = HashMap::new();
        for &(r, c, ref v) in &self.entries {
            rows_map.entry(r).or_insert_with(Vec::new).push((c, *v));
        }
        
        // Compute each row in parallel
        let mut result = vec![F::zero(); self.num_rows];
        result.par_iter_mut().enumerate().for_each(|(row_idx, result_val)| {
            if let Some(row_entries) = rows_map.get(&row_idx) {
                *result_val = row_entries.iter()
                    .map(|(c, v)| *v * vector[*c])
                    .fold(F::zero(), |acc, x| acc + x);
            }
        });
        
        result
    }

    /// Hadamard product of two vectors of equal length
    /// Uses parallel iteration for large vectors
    pub fn hadamard(a: &[F], b: &[F]) -> Vec<F> {
        assert_eq!(a.len(), b.len(), "hadamard length mismatch");
        
        const PARALLEL_THRESHOLD: usize = 1024; // 2^10
        
        if a.len() >= PARALLEL_THRESHOLD {
            // Parallel Hadamard product
            a.par_iter().zip(b.par_iter()).map(|(x, y)| *x * *y).collect()
        } else {
            // Sequential Hadamard product
            a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use ark_ff::One;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn test_mul_vector() {
        // Matrix:
        // [2 0]
        // [0 3]
        let mut m = SparseMatrix::new(2, 2);
        m.add_entry(0, 0, Fr::from(2u64));
        m.add_entry(1, 1, Fr::from(3u64));

        let v = vec![Fr::from(5u64), Fr::from(7u64)];
        let res = m.mul_vector(&v);
        assert_eq!(res[0], Fr::from(10u64));
        assert_eq!(res[1], Fr::from(21u64));
    }

    #[test]
    fn test_hadamard() {
        let a = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let h = SparseMatrix::hadamard(&a, &b);
        assert_eq!(h, vec![Fr::from(4u64), Fr::from(10u64), Fr::from(18u64)]);
    }

    #[test]
    fn test_bounds() {
        let mut m = SparseMatrix::<Fr>::new(1, 1);
        m.add_entry(0, 0, Fr::one());
        // Out of bounds should panic
        let result = catch_unwind(AssertUnwindSafe(|| m.add_entry(1, 0, Fr::one())));
        assert!(result.is_err());
    }
}

