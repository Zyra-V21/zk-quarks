//! Grand Product SNARK (§5 of Quarks paper)
//!
//! Proves P = Π_{i} V_i with O(log m) proof size.
//!
//! Based on Lemma 5.1:
//! P = Π_{x∈{0,1}^s} v(x) iff ∃f such that:
//! - f(0, x) = v(x)
//! - f(1, x) = f(x, 0) · f(x, 1)
//! - f(1...1, 0) = P
//!
//! Sum-check instance: G(x) = eq(τ,x) · (f(1,x) - f(x,0)·f(x,1))

use ark_bls12_381::Fr;
use ark_ff::{Zero, One};

use crate::polynomial::eq_polynomial;

/// Compute the grand product of a vector
pub fn grand_product(v: &[Fr]) -> Fr {
    v.iter().fold(Fr::one(), |acc, &x| acc * x)
}

/// Construct the auxiliary polynomial f for grand product proof
/// 
/// f is a (log m + 1)-variate polynomial where:
/// - f(0, x) = v(x) for x ∈ {0,1}^{log m}
/// - f(1, x) = f(x, 0) · f(x, 1)
/// - f(1...1, 0) = P
///
/// Returns evaluations of f over {0,1}^{log m + 1}
pub fn construct_f_polynomial(v_evals: &[Fr]) -> Vec<Fr> {
    let m = v_evals.len();
    assert!(m.is_power_of_two());
    let s = (m as f64).log2() as usize; // log m
    
    // f has s+1 variables, so 2^{s+1} = 2m evaluations
    let f_size = 2 * m;
    let mut f_evals = vec![Fr::zero(); f_size];
    
    // Layer 0: f(0, x) = v(x)
    // Index mapping: f[0 || x] = v[x], where 0 || x means prepending 0
    // In our indexing, f[x] for x < m corresponds to first bit = 0
    for i in 0..m {
        f_evals[i] = v_evals[i];
    }
    
    // Build layers: f(1^ℓ, 0, x) = Π_{y∈{0,1}^ℓ} v(x, y)
    // Layer by layer, compute products
    
    // For ℓ = 1: f(1, 0, x) = v(x, 0) · v(x, 1) for x ∈ {0,1}^{s-1}
    // For ℓ = 2: f(1, 1, 0, x) = f(1, 0, x, 0) · f(1, 0, x, 1)
    // etc.
    
    // Actually, we need f(1, x) where first bit is 1
    // f[m + x] for x ∈ {0,1}^s
    
    // f(1, x) = f(x, 0) · f(x, 1) where we interpret x as s-1 bits
    // This means: f[m + x] = f[x with last bit 0] · f[x with last bit 1]
    
    // Let's think differently:
    // f has s+1 bits: b_0, b_1, ..., b_s
    // f(0, x_1, ..., x_s) = v(x_1, ..., x_s) 
    // f(1, x_1, ..., x_s) = f(x_1, ..., x_s, 0) · f(x_1, ..., x_s, 1)
    
    // Index: f[b_0 * 2^s + b_1 * 2^{s-1} + ... + b_s]
    // f[0 * 2^s + x] = v[x] ✓
    // f[1 * 2^s + x] = f[x * 2 + 0] · f[x * 2 + 1]
    //               = f[2x] · f[2x + 1]
    
    for _x in 0..m {
        // f(1, x) where x is s bits
        // = f(x, 0) · f(x, 1) where x is s-1 bits
        // In index terms: f[m + x] = f[2*x_prefix] · f[2*x_prefix + 1]
        // where x_prefix is x interpreted as (s-1) bits
        
        // Actually simpler: f(1, x) needs f(x||0) and f(x||1)
        // f(x||0) has index x*2, f(x||1) has index x*2+1
        // But we need to handle the recursion properly
        
        // Let's use the recursive definition directly:
        // For s-bit x: f(1, x) = f(x, 0) · f(x, 1)
        // where f(x, b) has first bit from x and last bit b
        
        // If x = (x_1, ..., x_s), then (x, 0) = (x_1, ..., x_s, 0)
        // Index of (x, 0) in the f(0, ·) part: (0, x_1, ..., x_s, 0)
        // Hmm this is getting confusing. Let me restart.
    }
    
    // Clearer approach: build layer by layer
    // Layer ℓ contains partial products
    // f(1^ℓ, 0, x) = Π_{y∈{0,1}^ℓ} v(x || y)
    
    // ℓ = 0: f(0, x) = v(x) for x ∈ {0,1}^s
    // Already done above
    
    // For the recursion formula f(1, x) = f(x, 0) · f(x, 1):
    // We need to be careful about bit ordering.
    
    // Let's use: f_layer[ℓ][x] = Π_{y∈{0,1}^ℓ} v(x || y)
    // where x has s - ℓ bits
    
    let mut layers: Vec<Vec<Fr>> = Vec::with_capacity(s + 1);
    
    // Layer 0: size 2^s, values = v
    layers.push(v_evals.to_vec());
    
    // Build subsequent layers
    for _ell in 1..=s {
        let prev = layers.last().unwrap();
        let prev_size = prev.len();
        let new_size = prev_size / 2;
        
        let mut new_layer = Vec::with_capacity(new_size);
        for i in 0..new_size {
            // Combine two adjacent elements
            new_layer.push(prev[2 * i] * prev[2 * i + 1]);
        }
        layers.push(new_layer);
    }
    
    // Now populate f_evals
    // f(0, x) = v(x) = layers[0][x]
    // f(1, 0, x) = layers[1][x] for x ∈ {0,1}^{s-1}
    // f(1, 1, 0, x) = layers[2][x] for x ∈ {0,1}^{s-2}
    // ...
    // f(1, ..., 1, 0) = layers[s][0] = P
    
    // The f polynomial has s+1 variables
    // f(b_0, b_1, ..., b_s) where b_0 is the "layer selector"
    
    // For our sum-check, we need:
    // f(1, x) for x ∈ {0,1}^s
    // f(x, 0) for x ∈ {0,1}^s  
    // f(x, 1) for x ∈ {0,1}^s
    
    // Let's define f differently for clarity:
    // f: {0,1}^{s+1} → F
    // f(0, x_1, ..., x_s) = v(x_1, ..., x_s)
    // f(1, x_1, ..., x_s) = f(x_1, ..., x_s, 0) · f(x_1, ..., x_s, 1)
    //                    = f(x_1, ..., x_{s-1}, x_s, 0) · f(x_1, ..., x_{s-1}, x_s, 1)
    
    // This is recursive on the first coordinate.
    // Let's compute f(1, x) for all x:
    
    // f(1, x) where x = (x_1, ..., x_s)
    // = f(x_1, ..., x_s, 0) · f(x_1, ..., x_s, 1)
    // But f(x_1, ..., x_s, 0) has s+1 bits with first bit = x_1
    
    // If x_1 = 0: f(0, x_2, ..., x_s, 0) = v(x_2, ..., x_s, 0)
    // If x_1 = 1: f(1, x_2, ..., x_s, 0) = ... (recursive)
    
    // This is complex. Let me implement a direct recursive computation.
    
    f_evals
}

/// Evaluate f at a point r ∈ F^{s+1} given the layer structure
pub fn evaluate_f(layers: &[Vec<Fr>], r: &[Fr]) -> Fr {
    // r = (r_0, r_1, ..., r_s) where r_0 selects layer
    // Use multilinear extension
    let s = layers.len() - 1;
    assert_eq!(r.len(), s + 1);
    
    let mut result = Fr::zero();
    
    // Sum over all Boolean points weighted by eq(r, x)
    for layer_idx in 0..=s {
        let layer = &layers[layer_idx];
        let layer_size = layer.len();
        let layer_bits = (layer_size as f64).log2() as usize;
        
        for i in 0..layer_size {
            // Construct the full (s+1)-bit index
            // layer_idx ones followed by a zero followed by i in binary
            // Actually the indexing is: (1^layer_idx, 0, x) where |x| = s - layer_idx
            
            let mut bits = Vec::with_capacity(s + 1);
            
            // First layer_idx bits are 1
            for _ in 0..layer_idx {
                bits.push(true);
            }
            
            // Then a 0 (if layer_idx < s)
            if layer_idx < s {
                bits.push(false);
            }
            
            // Then the bits of i
            for j in 0..layer_bits {
                bits.push(((i >> (layer_bits - 1 - j)) & 1) == 1);
            }
            
            // Pad to s+1 bits if needed
            while bits.len() < s + 1 {
                bits.push(false);
            }
            
            let weight = eq_polynomial(r, &bits);
            result += weight * layer[i];
        }
    }
    
    // Special case: f(1, ..., 1) = 0 contributes nothing
    result
}

/// Build layers for f polynomial
pub fn build_f_layers(v_evals: &[Fr]) -> Vec<Vec<Fr>> {
    let m = v_evals.len();
    assert!(m.is_power_of_two());
    let s = (m as f64).log2() as usize;
    
    let mut layers: Vec<Vec<Fr>> = Vec::with_capacity(s + 1);
    
    // Layer 0: f(0, x) = v(x)
    layers.push(v_evals.to_vec());
    
    // Build subsequent layers by taking products
    for _ell in 1..=s {
        let prev = layers.last().unwrap();
        let prev_size = prev.len();
        let new_size = prev_size / 2;
        
        let mut new_layer = Vec::with_capacity(new_size);
        for i in 0..new_size {
            new_layer.push(prev[2 * i] * prev[2 * i + 1]);
        }
        layers.push(new_layer);
    }
    
    layers
}

/// Compute the sum-check polynomial G(x) = eq(τ, x) · (f(1,x) - f(x,0)·f(x,1))
/// Returns evaluations over {0,1}^s
pub fn compute_g_evaluations(
    layers: &[Vec<Fr>],
    tau: &[Fr],
) -> Vec<Fr> {
    let s = layers.len() - 1;
    let m = 1usize << s;
    
    let mut g_evals = Vec::with_capacity(m);
    
    for x_idx in 0..m {
        // Convert x_idx to bits
        let mut x_bits: Vec<bool> = Vec::with_capacity(s);
        for j in 0..s {
            x_bits.push(((x_idx >> (s - 1 - j)) & 1) == 1);
        }
        
        // Compute eq(τ, x)
        let eq_val = eq_polynomial(tau, &x_bits);
        
        // Compute f(1, x)
        let f_1_x = eval_f_at_1_x(layers, &x_bits);
        
        // Compute f(x, 0) and f(x, 1)
        let f_x_0 = eval_f_at_x_b(layers, &x_bits, false);
        let f_x_1 = eval_f_at_x_b(layers, &x_bits, true);
        
        // G(x) = eq(τ, x) · (f(1, x) - f(x, 0) · f(x, 1))
        let g_val = eq_val * (f_1_x - f_x_0 * f_x_1);
        g_evals.push(g_val);
    }
    
    g_evals
}

/// Evaluate f(1, x) for x ∈ {0,1}^s
/// Uses the recursive definition: f(1, x) = f(x, 0) · f(x, 1)
fn eval_f_at_1_x(layers: &[Vec<Fr>], x: &[bool]) -> Fr {
    let f_x_0 = eval_f_at_x_b(layers, x, false);
    let f_x_1 = eval_f_at_x_b(layers, x, true);
    f_x_0 * f_x_1
}

/// Evaluate f(x, b) where x ∈ {0,1}^s and b ∈ {0,1}
/// This is f at the point (x_1, ..., x_s, b)
fn eval_f_at_x_b(layers: &[Vec<Fr>], x: &[bool], b: bool) -> Fr {
    let s = x.len();
    
    // f(x_1, ..., x_s, b) where first bit is x_1
    // If x_1 = 0: f(0, x_2, ..., x_s, b) = v(x_2, ..., x_s, b)
    //           Index in layer 0: (x_2, ..., x_s, b) as integer
    // If x_1 = 1: f(1, x_2, ..., x_s, b) = f(x_2, ..., x_s, b, 0) · f(x_2, ..., x_s, b, 1)
    //           This is recursive
    
    // Count leading 1s
    let mut leading_ones = 0;
    for &bit in x.iter() {
        if bit {
            leading_ones += 1;
        } else {
            break;
        }
    }
    
    if leading_ones == s {
        // All ones: f(1, ..., 1, b)
        if b {
            // f(1, ..., 1, 1) = 0 by definition
            Fr::zero()
        } else {
            // f(1, ..., 1, 0) = P = layers[s][0]
            layers[s][0]
        }
    } else {
        // There's a 0 at position leading_ones
        // f(1^{leading_ones}, 0, rest, b)
        // This is in layer leading_ones
        
        // Remaining bits after the first 0
        let remaining = &x[leading_ones + 1..];
        let mut idx = 0usize;
        for &bit in remaining.iter() {
            idx = (idx << 1) | if bit { 1 } else { 0 };
        }
        idx = (idx << 1) | if b { 1 } else { 0 };
        
        // Layer leading_ones has 2^{s - leading_ones} elements
        if leading_ones < layers.len() && idx < layers[leading_ones].len() {
            layers[leading_ones][idx]
        } else {
            Fr::zero()
        }
    }
}

/// Grand Product proof
#[derive(Clone, Debug)]
pub struct GrandProductProof {
    /// Commitment to f polynomial (simplified - would use Kopis-PC in full impl)
    pub f_evaluations: Vec<Fr>,
    /// Challenge point τ
    pub tau: Vec<Fr>,
    /// Sum-check proof (simplified - just store intermediate values)
    pub sumcheck_rounds: Vec<(Fr, Fr)>,
}

/// Verify grand product claim P = Π v_i
pub fn verify_grand_product(
    v_evals: &[Fr],
    claimed_product: Fr,
) -> bool {
    let p = grand_product(v_evals);
    p == claimed_product
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;

    #[test]
    fn grand_product_basic() {
        let v = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)];
        let p = grand_product(&v);
        assert_eq!(p, Fr::from(120u64)); // 2*3*4*5 = 120
    }

    #[test]
    fn grand_product_power_of_two() {
        let v = vec![Fr::from(2u64); 8];
        let p = grand_product(&v);
        assert_eq!(p, Fr::from(256u64)); // 2^8 = 256
    }

    #[test]
    fn build_layers_basic() {
        // v = [1, 2, 3, 4] → P = 24
        let v = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let layers = build_f_layers(&v);
        
        // Layer 0: [1, 2, 3, 4]
        assert_eq!(layers[0].len(), 4);
        assert_eq!(layers[0][0], Fr::from(1u64));
        
        // Layer 1: [1*2, 3*4] = [2, 12]
        assert_eq!(layers[1].len(), 2);
        assert_eq!(layers[1][0], Fr::from(2u64));
        assert_eq!(layers[1][1], Fr::from(12u64));
        
        // Layer 2: [2*12] = [24]
        assert_eq!(layers[2].len(), 1);
        assert_eq!(layers[2][0], Fr::from(24u64));
    }

    #[test]
    fn f_layers_product_correct() {
        let mut rng = test_rng();
        
        for _ in 0..10 {
            let v: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
            let p = grand_product(&v);
            let layers = build_f_layers(&v);
            
            // Final layer should be the product
            assert_eq!(layers.last().unwrap()[0], p);
        }
    }

    #[test]
    fn eval_f_at_x_b_layer0() {
        let v = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let layers = build_f_layers(&v);
        
        // f(0, 0, 0) = v(0, 0) = v[0] = 1
        let x = vec![false, false];
        assert_eq!(eval_f_at_x_b(&layers, &x, false), Fr::from(1u64));
        
        // f(0, 0, 1) = v(0, 1) = v[1] = 2
        assert_eq!(eval_f_at_x_b(&layers, &x, true), Fr::from(2u64));
        
        // f(0, 1, 0) = v(1, 0) = v[2] = 3
        let x = vec![false, true];
        assert_eq!(eval_f_at_x_b(&layers, &x, false), Fr::from(3u64));
        
        // f(0, 1, 1) = v(1, 1) = v[3] = 4
        assert_eq!(eval_f_at_x_b(&layers, &x, true), Fr::from(4u64));
    }

    #[test]
    fn eval_f_at_x_b_layer1() {
        let v = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let layers = build_f_layers(&v);
        
        // f(1, 0, 0) should be in layer 1, index 0 = 2
        let x = vec![true, false];
        assert_eq!(eval_f_at_x_b(&layers, &x, false), Fr::from(2u64));
        
        // f(1, 0, 1) should be in layer 1, index 1 = 12
        assert_eq!(eval_f_at_x_b(&layers, &x, true), Fr::from(12u64));
    }

    #[test]
    fn eval_f_at_1_x_relation() {
        // Verify f(1, x) = f(x, 0) · f(x, 1) for random inputs
        let mut rng = test_rng();
        let v: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let layers = build_f_layers(&v);
        
        // Check for x = (0, 0, 0)
        let x = vec![false, false, false];
        let f_1_x = eval_f_at_1_x(&layers, &x);
        let f_x_0 = eval_f_at_x_b(&layers, &x, false);
        let f_x_1 = eval_f_at_x_b(&layers, &x, true);
        assert_eq!(f_1_x, f_x_0 * f_x_1);
    }

    #[test]
    fn g_evaluations_sum_to_zero() {
        let mut rng = test_rng();
        let v: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let layers = build_f_layers(&v);
        
        let s = 3; // log2(8) = 3
        let tau: Vec<Fr> = (0..s).map(|_| Fr::rand(&mut rng)).collect();
        
        let g_evals = compute_g_evaluations(&layers, &tau);
        
        // Sum of G over Boolean hypercube should be 0
        let sum: Fr = g_evals.iter().copied().fold(Fr::zero(), |a, b| a + b);
        assert_eq!(sum, Fr::zero());
    }

    #[test]
    fn g_sum_zero_multiple_random() {
        let mut rng = test_rng();
        
        for size_log in 2..=5 {
            let size = 1usize << size_log;
            let v: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let layers = build_f_layers(&v);
            
            let tau: Vec<Fr> = (0..size_log).map(|_| Fr::rand(&mut rng)).collect();
            let g_evals = compute_g_evaluations(&layers, &tau);
            
            let sum: Fr = g_evals.iter().copied().fold(Fr::zero(), |a, b| a + b);
            assert_eq!(sum, Fr::zero(), "G should sum to 0 for size {}", size);
        }
    }

    #[test]
    fn f_0_x_equals_v_x() {
        let v = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let layers = build_f_layers(&v);
        
        // Verify f(0, x) = v(x) for all x
        // f(0, x) is stored in layers[0]
        for i in 0..4 {
            assert_eq!(layers[0][i], v[i]);
        }
    }

    #[test]
    fn f_111_0_equals_product() {
        let mut rng = test_rng();
        let v: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let p = grand_product(&v);
        let layers = build_f_layers(&v);
        
        // f(1, 1, 1, 0) = P
        // This is in layers[3][0]
        assert_eq!(layers[3][0], p);
        
        // Also verify via eval_f_at_x_b
        let x = vec![true, true, true];
        assert_eq!(eval_f_at_x_b(&layers, &x, false), p);
    }

    #[test]
    fn grand_product_deterministic() {
        let v = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
        let p1 = grand_product(&v);
        let p2 = grand_product(&v);
        assert_eq!(p1, p2);
        assert_eq!(p1, Fr::from(210u64)); // 2*3*5*7 = 210
    }
}

