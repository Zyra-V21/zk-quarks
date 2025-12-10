//! Sparse multilinear polynomial representation
//!
//! For polynomials where |support| << 2^ℓ, we store only non-zero entries.
//! This is crucial for Sparkle compiler efficiency.

use ark_ff::Field;
use crate::polynomial::eq_polynomial;
use super::MultilinearPolynomial;
use rayon::prelude::*;

/// Sparse multilinear polynomial: stores only non-zero evaluations
/// Entry (index, value) means G(bits(index)) = value
#[derive(Debug, Clone)]
pub struct SparseMultilinearPolynomial<F: Field> {
    /// Non-zero entries: (index, value) where index ∈ [0, 2^num_vars)
    pub entries: Vec<(usize, F)>,
    /// Number of variables ℓ
    pub num_vars: usize,
}

impl<F: Field> SparseMultilinearPolynomial<F> {
    /// Create empty sparse polynomial with given number of variables
    pub fn new(num_vars: usize) -> Self {
        Self {
            entries: Vec::new(),
            num_vars,
        }
    }

    /// Create from list of (index, value) pairs
    pub fn from_entries(entries: Vec<(usize, F)>, num_vars: usize) -> Self {
        let max_idx = 1usize << num_vars;
        for &(idx, _) in &entries {
            assert!(idx < max_idx, "index {} out of bounds for {} variables", idx, num_vars);
        }
        Self { entries, num_vars }
    }

    /// Number of non-zero entries (sparsity)
    pub fn num_nonzero(&self) -> usize {
        self.entries.len()
    }

    /// Domain size 2^ℓ
    pub fn domain_size(&self) -> usize {
        1usize << self.num_vars
    }

    /// Add a non-zero entry. Does not check for duplicates.
    pub fn add_entry(&mut self, index: usize, value: F) {
        let max_idx = 1usize << self.num_vars;
        assert!(index < max_idx, "index out of bounds");
        if !value.is_zero() {
            self.entries.push((index, value));
        }
    }

    /// Convert index to Boolean vector (big-endian: MSB first)
    fn index_to_bits(&self, idx: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(self.num_vars);
        for i in 0..self.num_vars {
            let bit = ((idx >> (self.num_vars - 1 - i)) & 1) == 1;
            bits.push(bit);
        }
        bits
    }

    /// Evaluate at Boolean point e ∈ {0,1}^ℓ (given as bools)
    /// O(k) where k = number of non-zero entries
    pub fn eval_boolean(&self, e: &[bool]) -> F {
        assert_eq!(e.len(), self.num_vars);
        // Convert e to index
        let mut idx = 0usize;
        for &b in e {
            idx = (idx << 1) | if b { 1 } else { 0 };
        }
        // Search for entry (could use HashMap for O(1) but Vec is fine for now)
        for &(entry_idx, ref val) in &self.entries {
            if entry_idx == idx {
                return *val;
            }
        }
        F::zero()
    }

    /// Evaluate MLE at arbitrary point x ∈ F^ℓ
    /// O(k · ℓ) where k = number of non-zero entries
    /// Much faster than dense O(2^ℓ) when k << 2^ℓ
    /// Uses parallel evaluation for sparse polynomials with many entries
    pub fn evaluate(&self, x: &[F]) -> F {
        assert_eq!(x.len(), self.num_vars);
        
        const PARALLEL_THRESHOLD: usize = 256; // Parallelize if ≥256 non-zero entries
        
        if self.entries.len() >= PARALLEL_THRESHOLD {
            // Parallel evaluation for sparse polynomials with many non-zero entries
            self.entries
                .par_iter()
                .map(|&(idx, ref val)| {
                    let bits = self.index_to_bits(idx);
                    let weight = eq_polynomial(x, &bits);
                    *val * weight
                })
                .reduce(|| F::zero(), |a, b| a + b)
        } else {
            // Sequential evaluation for very sparse polynomials (less overhead)
            let mut acc = F::zero();
            for &(idx, ref val) in &self.entries {
                let bits = self.index_to_bits(idx);
                let weight = eq_polynomial(x, &bits);
                acc += *val * weight;
            }
            acc
        }
    }

    /// Convert to dense representation
    /// O(2^ℓ) space - use only when necessary
    pub fn to_dense(&self) -> MultilinearPolynomial<F> {
        let size = 1usize << self.num_vars;
        let mut evals = vec![F::zero(); size];
        for &(idx, ref val) in &self.entries {
            evals[idx] = *val;
        }
        MultilinearPolynomial::from_evaluations(evals, self.num_vars)
    }

    /// Create from dense representation, keeping only non-zero entries
    pub fn from_dense(dense: &MultilinearPolynomial<F>) -> Self {
        let mut entries = Vec::new();
        for (idx, val) in dense.evaluations.iter().enumerate() {
            if !val.is_zero() {
                entries.push((idx, *val));
            }
        }
        Self {
            entries,
            num_vars: dense.num_vars,
        }
    }

    /// Memory usage in field elements (sparse)
    pub fn memory_usage(&self) -> usize {
        self.entries.len() * 2 // each entry stores (index, value)
    }

    /// Memory usage if stored densely
    pub fn dense_memory_usage(&self) -> usize {
        1usize << self.num_vars
    }

    /// Sparsity ratio: actual / dense
    pub fn sparsity_ratio(&self) -> f64 {
        self.num_nonzero() as f64 / self.domain_size() as f64
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
    fn sparse_eval_boolean_matches_dense() {
        let mut rng = test_rng();
        let num_vars = 4;
        let size = 1usize << num_vars;

        // Create sparse polynomial with ~10% non-zero entries
        let mut sparse = SparseMultilinearPolynomial::new(num_vars);
        let num_nonzero = size / 10 + 1;
        let mut used_indices = std::collections::HashSet::new();

        for _ in 0..num_nonzero {
            let mut idx = rng.gen::<usize>() % size;
            while used_indices.contains(&idx) {
                idx = rng.gen::<usize>() % size;
            }
            used_indices.insert(idx);
            sparse.add_entry(idx, Fr::from(rng.gen::<u64>() % 100 + 1));
        }

        // Convert to dense
        let dense = sparse.to_dense();

        // Check all Boolean points
        for idx in 0..size {
            let mut bits = Vec::with_capacity(num_vars);
            for i in 0..num_vars {
                bits.push(((idx >> (num_vars - 1 - i)) & 1) == 1);
            }
            let sparse_val = sparse.eval_boolean(&bits);
            let dense_val = dense.eval_boolean(&bits);
            assert_eq!(sparse_val, dense_val, "mismatch at index {}", idx);
        }
    }

    #[test]
    fn sparse_mle_matches_dense_at_random_points() {
        let mut rng = test_rng();
        let num_vars = 5;
        let _size = 1usize << num_vars; // 32, for reference

        // Create sparse polynomial with 10 non-zero entries in 2^5 = 32 domain
        let mut sparse = SparseMultilinearPolynomial::new(num_vars);
        let entries = vec![
            (0, Fr::from(3u64)),
            (5, Fr::from(7u64)),
            (10, Fr::from(11u64)),
            (15, Fr::from(13u64)),
            (20, Fr::from(17u64)),
            (25, Fr::from(19u64)),
            (30, Fr::from(23u64)),
            (31, Fr::from(29u64)),
        ];
        for (idx, val) in entries {
            sparse.add_entry(idx, val);
        }

        let dense = sparse.to_dense();

        // Test at 50 random field points
        for _ in 0..50 {
            let x: Vec<Fr> = (0..num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
            let sparse_eval = sparse.evaluate(&x);
            let dense_eval = dense.evaluate(&x);
            assert_eq!(sparse_eval, dense_eval, "MLE mismatch at random point");
        }
    }

    #[test]
    fn sparse_large_domain_small_support() {
        // Test with 2^20 domain but only 10 non-zero entries
        let num_vars = 20;
        let size = 1usize << num_vars; // 1,048,576

        let mut sparse = SparseMultilinearPolynomial::new(num_vars);
        let entries = vec![
            (0, Fr::from(1u64)),
            (1, Fr::from(2u64)),
            (100, Fr::from(3u64)),
            (1000, Fr::from(4u64)),
            (10000, Fr::from(5u64)),
            (100000, Fr::from(6u64)),
            (500000, Fr::from(7u64)),
            (750000, Fr::from(8u64)),
            (900000, Fr::from(9u64)),
            (1048575, Fr::from(10u64)), // last index
        ];
        for (idx, val) in entries.clone() {
            sparse.add_entry(idx, val);
        }

        // Verify memory savings
        assert_eq!(sparse.num_nonzero(), 10);
        assert_eq!(sparse.domain_size(), size);
        assert!(sparse.memory_usage() << 10 < sparse.dense_memory_usage());
        assert!(sparse.sparsity_ratio() < 0.00001);

        // Verify evaluations at non-zero points
        for (idx, expected_val) in entries {
            let bits = sparse.index_to_bits(idx);
            let val = sparse.eval_boolean(&bits);
            assert_eq!(val, expected_val);
        }

        // Verify zero at a random unused index
        let unused_idx = 50000;
        let bits = sparse.index_to_bits(unused_idx);
        assert_eq!(sparse.eval_boolean(&bits), Fr::zero());
    }

    #[test]
    fn sparse_from_dense_roundtrip() {
        let mut rng = test_rng();
        let num_vars = 4;
        let size = 1usize << num_vars;

        // Create dense polynomial with some zeros
        let mut evals = Vec::with_capacity(size);
        for _ in 0..size {
            if rng.gen::<bool>() {
                evals.push(Fr::from(rng.gen::<u64>() % 100 + 1));
            } else {
                evals.push(Fr::zero());
            }
        }
        let dense = MultilinearPolynomial::from_evaluations(evals.clone(), num_vars);

        // Convert to sparse and back
        let sparse = SparseMultilinearPolynomial::from_dense(&dense);
        let dense2 = sparse.to_dense();

        // Check equality
        for idx in 0..size {
            assert_eq!(dense.evaluations[idx], dense2.evaluations[idx]);
        }
    }

    #[test]
    fn sparse_zero_polynomial() {
        let num_vars = 5;
        let sparse = SparseMultilinearPolynomial::<Fr>::new(num_vars);

        assert_eq!(sparse.num_nonzero(), 0);

        let mut rng = test_rng();
        for _ in 0..10 {
            let x: Vec<Fr> = (0..num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
            assert_eq!(sparse.evaluate(&x), Fr::zero());
        }
    }

    #[test]
    fn sparse_single_entry() {
        let num_vars = 3;
        let mut sparse = SparseMultilinearPolynomial::new(num_vars);
        sparse.add_entry(5, Fr::from(42u64)); // index 5 = bits 101

        // At point (1, 0, 1) should be 42
        let x = vec![Fr::one(), Fr::zero(), Fr::one()];
        assert_eq!(sparse.evaluate(&x), Fr::from(42u64));

        // At point (0, 0, 0) should be 0
        let x = vec![Fr::zero(), Fr::zero(), Fr::zero()];
        assert_eq!(sparse.evaluate(&x), Fr::zero());

        // At other Boolean points should be 0
        let x = vec![Fr::one(), Fr::one(), Fr::one()];
        assert_eq!(sparse.evaluate(&x), Fr::zero());
    }

    #[test]
    fn sparse_mle_linearity() {
        let mut rng = test_rng();
        let num_vars = 4;

        // Create two sparse polynomials
        let mut f = SparseMultilinearPolynomial::new(num_vars);
        f.add_entry(0, Fr::from(5u64));
        f.add_entry(3, Fr::from(7u64));
        f.add_entry(10, Fr::from(11u64));

        let mut g = SparseMultilinearPolynomial::new(num_vars);
        g.add_entry(0, Fr::from(2u64));
        g.add_entry(5, Fr::from(3u64));
        g.add_entry(10, Fr::from(4u64));

        // Create h = f + g (manually)
        let mut h = SparseMultilinearPolynomial::new(num_vars);
        h.add_entry(0, Fr::from(7u64));  // 5 + 2
        h.add_entry(3, Fr::from(7u64));  // 7 + 0
        h.add_entry(5, Fr::from(3u64));  // 0 + 3
        h.add_entry(10, Fr::from(15u64)); // 11 + 4

        // Test MLE linearity at random points
        for _ in 0..20 {
            let x: Vec<Fr> = (0..num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
            let lhs = h.evaluate(&x);
            let rhs = f.evaluate(&x) + g.evaluate(&x);
            assert_eq!(lhs, rhs, "MLE linearity failed");
        }
    }
}

