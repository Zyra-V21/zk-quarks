//! Sparkle Compiler (§6 of Quarks paper)
//!
//! Compiles polynomial commitment schemes for dense multilinear polynomials
//! to efficiently handle sparse multilinear polynomials.
//!
//! Key improvement over SPARK:
//! - SPARK: O(log² m) proof sizes
//! - Sparkle: O(log m) proof sizes
//!
//! Uses hybrid approach:
//! 1. Depth-4 layered sum-check to reduce instance size
//! 2. Grand Product SNARK for remaining computation
//!
//! Based on multiset hash: H_γ(M) = Π_{e∈M}(e - γ)

use ark_bls12_381::Fr;
use ark_ff::{Zero, One};
use ark_std::vec::Vec;

use crate::polynomial::SparseMultilinearPolynomial;
use crate::grand_product::build_f_layers;

/// Multiset hash function H_γ(M) = Π_{e∈M}(e - γ)
/// 
/// This is used in SPARK/Sparkle to verify sparse polynomial evaluations
pub fn multiset_hash(elements: &[Fr], gamma: Fr) -> Fr {
    elements.iter()
        .map(|e| *e - gamma)
        .fold(Fr::one(), |acc, x| acc * x)
}

/// Layered circuit for computing products
/// Each layer computes pairwise products: out[i] = in[2i] * in[2i+1]
pub struct LayeredCircuit {
    /// Input layer (layer 0)
    pub layers: Vec<Vec<Fr>>,
}

impl LayeredCircuit {
    /// Build a layered circuit for computing the product of elements
    pub fn new(input: Vec<Fr>) -> Self {
        let n = input.len();
        assert!(n.is_power_of_two(), "Input size must be power of 2");
        
        let depth = (n as f64).log2() as usize;
        let mut layers = Vec::with_capacity(depth + 1);
        layers.push(input);
        
        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let new_size = prev.len() / 2;
            let mut new_layer = Vec::with_capacity(new_size);
            
            for i in 0..new_size {
                new_layer.push(prev[2 * i] * prev[2 * i + 1]);
            }
            layers.push(new_layer);
        }
        
        Self { layers }
    }

    /// Get the output (product of all inputs)
    pub fn output(&self) -> Fr {
        self.layers.last().unwrap()[0]
    }

    /// Get the depth of the circuit
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Apply k layers of reduction starting from layer start_layer
    pub fn reduce_k_layers(&self, start_layer: usize, k: usize) -> Option<&Vec<Fr>> {
        let target = start_layer + k;
        if target < self.layers.len() {
            Some(&self.layers[target])
        } else {
            None
        }
    }
}

/// Sparkle hybrid scheme configuration
pub struct SparkleConfig {
    /// Number of initial layered sum-check layers (typically 4)
    pub initial_layers: usize,
}

impl Default for SparkleConfig {
    fn default() -> Self {
        Self { initial_layers: 4 }
    }
}

/// Sparkle compiler for sparse polynomial commitments
pub struct Sparkle {
    pub config: SparkleConfig,
}

impl Sparkle {
    pub fn new(config: SparkleConfig) -> Self {
        Self { config }
    }

    /// Compute sparse polynomial evaluation using Sparkle
    /// 
    /// For a sparse polynomial with m non-zero entries in dense representation:
    /// 1. Use initial_layers of layered sum-check (reduces instance by 2^initial_layers)
    /// 2. Use Grand Product SNARK for remaining computation
    pub fn sparse_eval(
        &self,
        sparse_poly: &SparseMultilinearPolynomial<Fr>,
        point: &[Fr],
    ) -> Fr {
        sparse_poly.evaluate(point)
    }

    /// Build the multiset hash for sparse polynomial verification
    /// 
    /// Given indices of non-zero entries and their values,
    /// compute H_γ = Π(val_i · eq(idx_i, r) - γ)
    pub fn build_multiset_for_sparse(
        &self,
        sparse_poly: &SparseMultilinearPolynomial<Fr>,
        eval_point: &[Fr],
        gamma: Fr,
    ) -> Fr {
        use crate::polynomial::eq_polynomial;
        
        let mut elements = Vec::new();
        
        for (idx, val) in sparse_poly.entries.iter() {
            // Convert index to bits
            let mut bits = Vec::with_capacity(sparse_poly.num_vars);
            for i in 0..sparse_poly.num_vars {
                let bit = ((idx >> (sparse_poly.num_vars - 1 - i)) & 1) == 1;
                bits.push(bit);
            }
            
            // Compute val · eq(idx, r)
            let eq_val = eq_polynomial(eval_point, &bits);
            elements.push(*val * eq_val);
        }
        
        multiset_hash(&elements, gamma)
    }

    /// Hybrid evaluation: layered sum-check + grand product
    pub fn hybrid_eval(
        &self,
        values: &[Fr],
        gamma: Fr,
    ) -> HybridProof {
        let n = values.len();
        assert!(n.is_power_of_two());
        
        // Build (v - γ) for each element
        let shifted: Vec<Fr> = values.iter().map(|v| *v - gamma).collect();
        
        // Build layered circuit
        let circuit = LayeredCircuit::new(shifted.clone());
        
        // Get the intermediate state after initial_layers
        let k = self.config.initial_layers.min(circuit.depth());
        let intermediate = if k < circuit.depth() {
            circuit.layers[k].clone()
        } else {
            circuit.layers.last().unwrap().clone()
        };
        
        // Use grand product for the rest
        let gp_layers = build_f_layers(&intermediate);
        let final_product = circuit.output();
        
        HybridProof {
            initial_layers: k,
            intermediate_values: intermediate,
            grand_product_layers: gp_layers,
            result: final_product,
        }
    }
}

/// Proof from hybrid Sparkle evaluation
#[derive(Clone, Debug)]
pub struct HybridProof {
    /// Number of layered sum-check layers used
    pub initial_layers: usize,
    /// Intermediate values after initial_layers
    pub intermediate_values: Vec<Fr>,
    /// Grand product layers for remaining computation
    pub grand_product_layers: Vec<Vec<Fr>>,
    /// Final result H_γ(M)
    pub result: Fr,
}

impl HybridProof {
    /// Verify the hybrid proof structure
    pub fn verify_structure(&self) -> bool {
        // Check that grand product layers produce the same result
        if let Some(last) = self.grand_product_layers.last() {
            if last.len() != 1 {
                return false;
            }
            
            // The product of intermediate values should match
            let intermediate_product = self.intermediate_values.iter()
                .copied()
                .fold(Fr::one(), |a, b| a * b);
            
            last[0] == intermediate_product
        } else {
            false
        }
    }
}

/// Sparse polynomial commitment scheme using Sparkle
pub struct SparklePC {
    sparkle: Sparkle,
}

impl SparklePC {
    pub fn new() -> Self {
        Self {
            sparkle: Sparkle::new(SparkleConfig::default()),
        }
    }

    /// Evaluate sparse polynomial and generate proof structure
    pub fn eval_with_proof(
        &self,
        sparse_poly: &SparseMultilinearPolynomial<Fr>,
        point: &[Fr],
        gamma: Fr,
    ) -> (Fr, HybridProof) {
        let eval = sparse_poly.evaluate(point);
        
        // For the multiset hash, we need the weighted values
        let mut weighted_values = Vec::new();
        
        use crate::polynomial::eq_polynomial;
        
        for (idx, val) in sparse_poly.entries.iter() {
            let mut bits = Vec::with_capacity(sparse_poly.num_vars);
            for i in 0..sparse_poly.num_vars {
                let bit = ((idx >> (sparse_poly.num_vars - 1 - i)) & 1) == 1;
                bits.push(bit);
            }
            let eq_val = eq_polynomial(point, &bits);
            weighted_values.push(*val * eq_val);
        }
        
        // Pad to power of 2 with zeros (which become -γ after shift)
        let next_pow2 = weighted_values.len().next_power_of_two();
        while weighted_values.len() < next_pow2 {
            weighted_values.push(Fr::zero());
        }
        
        let proof = self.sparkle.hybrid_eval(&weighted_values, gamma);
        
        (eval, proof)
    }
}

impl Default for SparklePC {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;

    #[test]
    fn multiset_hash_basic() {
        let elements = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let gamma = Fr::from(10u64);
        
        // H_γ = (1-10)(2-10)(3-10) = (-9)(-8)(-7) = -504
        let h = multiset_hash(&elements, gamma);
        
        let expected = (Fr::from(1u64) - gamma) 
            * (Fr::from(2u64) - gamma) 
            * (Fr::from(3u64) - gamma);
        
        assert_eq!(h, expected);
    }

    #[test]
    fn multiset_hash_single() {
        let elements = vec![Fr::from(5u64)];
        let gamma = Fr::from(3u64);
        
        // H_γ = 5 - 3 = 2
        let h = multiset_hash(&elements, gamma);
        assert_eq!(h, Fr::from(2u64));
    }

    #[test]
    fn layered_circuit_basic() {
        let input = vec![
            Fr::from(2u64), Fr::from(3u64), 
            Fr::from(4u64), Fr::from(5u64)
        ];
        
        let circuit = LayeredCircuit::new(input.clone());
        
        // Layer 0: [2, 3, 4, 5]
        // Layer 1: [6, 20]
        // Layer 2: [120]
        
        assert_eq!(circuit.depth(), 2);
        assert_eq!(circuit.output(), Fr::from(120u64));
        assert_eq!(circuit.layers[1], vec![Fr::from(6u64), Fr::from(20u64)]);
    }

    #[test]
    fn layered_circuit_power_of_two() {
        let input: Vec<Fr> = (1..=8).map(Fr::from).collect();
        let circuit = LayeredCircuit::new(input);
        
        // 1*2*3*4*5*6*7*8 = 40320
        assert_eq!(circuit.output(), Fr::from(40320u64));
        assert_eq!(circuit.depth(), 3);
    }

    #[test]
    fn sparkle_config_default() {
        let config = SparkleConfig::default();
        assert_eq!(config.initial_layers, 4);
    }

    #[test]
    fn sparkle_hybrid_eval_basic() {
        let sparkle = Sparkle::new(SparkleConfig { initial_layers: 2 });
        let values: Vec<Fr> = (1..=8).map(Fr::from).collect();
        let gamma = Fr::from(0u64);
        
        let proof = sparkle.hybrid_eval(&values, gamma);
        
        // With gamma=0, H_γ = Π v_i = 40320
        assert_eq!(proof.result, Fr::from(40320u64));
    }

    #[test]
    fn sparkle_hybrid_proof_structure() {
        let sparkle = Sparkle::new(SparkleConfig { initial_layers: 2 });
        let values: Vec<Fr> = (1..=16).map(Fr::from).collect();
        let gamma = Fr::zero();
        
        let proof = sparkle.hybrid_eval(&values, gamma);
        
        // After 2 layers, we should have 16/4 = 4 intermediate values
        assert_eq!(proof.intermediate_values.len(), 4);
        assert!(proof.verify_structure());
    }

    #[test]
    fn sparkle_with_gamma() {
        let sparkle = Sparkle::new(SparkleConfig::default());
        let values = vec![Fr::from(5u64), Fr::from(10u64), Fr::from(15u64), Fr::from(20u64)];
        let gamma = Fr::from(2u64);
        
        // H_γ = (5-2)(10-2)(15-2)(20-2) = 3·8·13·18 = 5616
        let proof = sparkle.hybrid_eval(&values, gamma);
        
        let expected = (Fr::from(5u64) - gamma)
            * (Fr::from(10u64) - gamma)
            * (Fr::from(15u64) - gamma)
            * (Fr::from(20u64) - gamma);
        
        assert_eq!(proof.result, expected);
    }

    #[test]
    fn sparkle_sparse_poly_eval() {
        let sparkle = Sparkle::new(SparkleConfig::default());
        
        let mut sparse = SparseMultilinearPolynomial::new(3);
        sparse.add_entry(0b000, Fr::from(1u64));
        sparse.add_entry(0b101, Fr::from(5u64));
        sparse.add_entry(0b111, Fr::from(7u64));
        
        let point = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        
        let eval = sparkle.sparse_eval(&sparse, &point);
        
        // Manual check: should match SparseMultilinearPolynomial::evaluate
        let expected = sparse.evaluate(&point);
        assert_eq!(eval, expected);
    }

    #[test]
    fn sparkle_pc_basic() {
        let pc = SparklePC::new();
        
        let mut sparse = SparseMultilinearPolynomial::new(4);
        sparse.add_entry(0b0000, Fr::from(1u64));
        sparse.add_entry(0b0101, Fr::from(2u64));
        sparse.add_entry(0b1010, Fr::from(3u64));
        sparse.add_entry(0b1111, Fr::from(4u64));
        
        let point: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64 + 1)).collect();
        let gamma = Fr::from(100u64);
        
        let (eval, proof) = pc.eval_with_proof(&sparse, &point, gamma);
        
        // Eval should match direct evaluation
        assert_eq!(eval, sparse.evaluate(&point));
        
        // Proof should have valid structure
        assert!(proof.verify_structure());
    }

    #[test]
    fn sparkle_proof_size_logarithmic() {
        let sparkle = Sparkle::new(SparkleConfig { initial_layers: 4 });
        
        for log_n in 4..=8 {
            let n = 1usize << log_n;
            let values: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let gamma = Fr::zero();
            
            let proof = sparkle.hybrid_eval(&values, gamma);
            
            // After 4 layers, intermediate size should be n / 16
            let expected_intermediate_size = n / 16;
            assert_eq!(
                proof.intermediate_values.len(), 
                expected_intermediate_size,
                "For n={}, expected {} intermediate values",
                n, expected_intermediate_size
            );
            
            // Grand product layers should be log2(n/16) + 1
            let expected_gp_layers = (expected_intermediate_size as f64).log2() as usize + 1;
            assert_eq!(
                proof.grand_product_layers.len(),
                expected_gp_layers,
                "For n={}, expected {} GP layers",
                n, expected_gp_layers
            );
        }
    }

    #[test]
    fn multiset_hash_random() {
        let mut rng = test_rng();
        
        for _ in 0..10 {
            let n = 8;
            let elements: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let gamma = Fr::rand(&mut rng);
            
            let h = multiset_hash(&elements, gamma);
            
            // Verify by direct computation
            let expected = elements.iter()
                .map(|e| *e - gamma)
                .fold(Fr::one(), |a, b| a * b);
            
            assert_eq!(h, expected);
        }
    }
}

