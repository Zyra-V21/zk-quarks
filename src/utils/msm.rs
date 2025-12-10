//! Multi-Scalar Multiplication (MSM) using Pippenger's Algorithm
//!
//! Pippenger's algorithm reduces MSM complexity from O(n) to O(n/log n)
//! for computing Σ scalar_i * point_i over elliptic curve points.
//!
//! Reference: "On the Evaluation of Modular Polynomials" - Pippenger (1976)

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, BigInteger};
use rayon::prelude::*;

/// Multi-scalar multiplication: Σ scalars[i] * points[i]
/// 
/// Uses Pippenger's bucket method with affine coordinate optimization:
/// - Naive: O(n) scalar multiplications
/// - Pippenger: O(n/log n) complexity with bucket aggregation
/// - Affine optimization: ~20-30% faster via mixed addition
/// 
/// # Arguments
/// * `points` - Vector of curve points (G1, G2, etc.)
/// * `scalars` - Vector of scalar multipliers
/// 
/// # Returns
/// The result of Σ scalars[i] * points[i]
pub fn msm<G: CurveGroup>(points: &[G], scalars: &[G::ScalarField]) -> G {
    assert_eq!(points.len(), scalars.len(), "MSM: points and scalars length mismatch");
    
    let n = points.len();
    
    // Thresholds for algorithm selection
    const NAIVE_THRESHOLD: usize = 32;  // Use naive for very small n
    const AFFINE_THRESHOLD: usize = 64;  // Use affine optimization above this
    const PARALLEL_THRESHOLD: usize = 256;  // Parallelize for larger n
    
    if n == 0 {
        return G::zero();
    } else if n == 1 {
        return points[0] * scalars[0];
    } else if n < NAIVE_THRESHOLD {
        return msm_naive(points, scalars);
    } else if n < AFFINE_THRESHOLD {
        return msm_pippenger_sequential(points, scalars);
    } else if n < PARALLEL_THRESHOLD {
        return msm_pippenger_affine_sequential(points, scalars);
    } else {
        return msm_pippenger_affine_parallel(points, scalars);
    }
}

/// Naive MSM: Σ scalars[i] * points[i] using sequential scalar multiplication
/// O(n) complexity - used only for very small n where overhead dominates
fn msm_naive<G: CurveGroup>(points: &[G], scalars: &[G::ScalarField]) -> G {
    points.iter()
        .zip(scalars.iter())
        .map(|(p, s)| *p * s)
        .fold(G::zero(), |acc, p| acc + p)
}

/// Pippenger's algorithm (sequential) - O(n/log n)
/// 
/// Algorithm:
/// 1. Choose bucket window size c (typically log2(n))
/// 2. For each window of c bits in scalars:
///    - Accumulate points into 2^c buckets based on bit pattern
///    - Combine buckets: bucket[i] contributes i times
/// 3. Combine windows with appropriate shifts (doubling)
fn msm_pippenger_sequential<G: CurveGroup>(points: &[G], scalars: &[G::ScalarField]) -> G {
    let n = points.len();
    if n == 0 {
        return G::zero();
    }
    
    // Optimal window size: c ≈ log2(n)
    // Trade-off: smaller c → fewer buckets, more iterations
    //           larger c → more buckets, fewer iterations
    let c = optimal_window_size(n);
    let num_buckets = 1usize << c;  // 2^c buckets
    
    // Get bit length of scalars (BLS12-381: 255 bits)
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let num_windows = (scalar_bits + c - 1) / c;  // Ceiling division
    
    let mut result = G::zero();
    
    // Process windows from most significant to least significant
    for window_idx in (0..num_windows).rev() {
        // Double the accumulator c times (shift left by c bits)
        for _ in 0..c {
            result = result.double();
        }
        
        // Initialize buckets for this window
        let mut buckets: Vec<G> = vec![G::zero(); num_buckets];
        
        // Accumulate points into buckets based on scalar bits in this window
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            let bucket_idx = extract_window_bits(scalar, window_idx, c, scalar_bits);
            if bucket_idx > 0 {
                buckets[bucket_idx] += point;
            }
        }
        
        // Combine buckets: bucket[i] contributes i times
        // Use running sum technique: sum = Σ i * buckets[i]
        // Optimization: running_sum[i] = Σ_{j=i}^{2^c-1} buckets[j]
        let window_sum = combine_buckets(&buckets);
        result += window_sum;
    }
    
    result
}

/// Pippenger's algorithm with affine coordinates (sequential)
/// Uses mixed addition (affine + projective → projective) for ~20% speedup
fn msm_pippenger_affine_sequential<G: CurveGroup>(points: &[G], scalars: &[G::ScalarField]) -> G {
    let n = points.len();
    if n == 0 {
        return G::zero();
    }
    
    // Convert points to affine for faster mixed addition
    let points_affine: Vec<G::Affine> = G::normalize_batch(points);
    
    let c = optimal_window_size(n);
    let num_buckets = 1usize << c;
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let num_windows = (scalar_bits + c - 1) / c;
    
    let mut result = G::zero();
    
    for window_idx in (0..num_windows).rev() {
        for _ in 0..c {
            result = result.double();
        }
        
        // Accumulate into buckets using mixed addition
        let mut buckets: Vec<G> = vec![G::zero(); num_buckets];
        
        for (point_affine, scalar) in points_affine.iter().zip(scalars.iter()) {
            let bucket_idx = extract_window_bits(scalar, window_idx, c, scalar_bits);
            if bucket_idx > 0 {
                // Mixed addition: affine + projective is faster than projective + projective
                buckets[bucket_idx] += *point_affine;
            }
        }
        
        let window_sum = combine_buckets(&buckets);
        result += window_sum;
    }
    
    result
}

/// Pippenger's algorithm with affine coordinates (parallel)
/// Combines affine optimization with parallel bucket accumulation
fn msm_pippenger_affine_parallel<G: CurveGroup>(points: &[G], scalars: &[G::ScalarField]) -> G 
where
    G: Send + Sync,
    G::ScalarField: Send + Sync,
    G::Affine: Send + Sync,
{
    let n = points.len();
    if n == 0 {
        return G::zero();
    }
    
    // Batch convert to affine (single inversion per point amortized)
    let points_affine: Vec<G::Affine> = G::normalize_batch(points);
    
    let c = optimal_window_size(n);
    let num_buckets = 1usize << c;
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let num_windows = (scalar_bits + c - 1) / c;
    
    let mut result = G::zero();
    
    for window_idx in (0..num_windows).rev() {
        for _ in 0..c {
            result = result.double();
        }
        
        // Parallel bucket accumulation with affine points
        let buckets: Vec<G> = accumulate_buckets_affine_parallel(
            &points_affine, 
            scalars, 
            window_idx, 
            c, 
            num_buckets, 
            scalar_bits
        );
        let window_sum = combine_buckets(&buckets);
        result += window_sum;
    }
    
    result
}

/// Accumulate affine points into buckets in parallel
fn accumulate_buckets_affine_parallel<G: CurveGroup>(
    points_affine: &[G::Affine],
    scalars: &[G::ScalarField],
    window_idx: usize,
    c: usize,
    num_buckets: usize,
    scalar_bits: usize,
) -> Vec<G>
where
    G: Send + Sync,
    G::ScalarField: Send + Sync,
    G::Affine: Send + Sync,
{
    const CHUNK_SIZE: usize = 256;
    
    let chunks: Vec<_> = points_affine.chunks(CHUNK_SIZE)
        .zip(scalars.chunks(CHUNK_SIZE))
        .collect();
    
    // Each thread accumulates its chunk into local buckets
    let local_bucket_vecs: Vec<Vec<G>> = chunks.par_iter()
        .map(|(point_chunk, scalar_chunk)| {
            let mut local_buckets = vec![G::zero(); num_buckets];
            for (point_affine, scalar) in point_chunk.iter().zip(scalar_chunk.iter()) {
                let bucket_idx = extract_window_bits(scalar, window_idx, c, scalar_bits);
                if bucket_idx > 0 {
                    // Mixed addition: affine + projective
                    local_buckets[bucket_idx] += *point_affine;
                }
            }
            local_buckets
        })
        .collect();
    
    // Merge local buckets
    let mut global_buckets = vec![G::zero(); num_buckets];
    for local_buckets in local_bucket_vecs {
        for (i, local_bucket) in local_buckets.into_iter().enumerate() {
            global_buckets[i] += local_bucket;
        }
    }
    
    global_buckets
}

/// Extract c bits from scalar at the given window position
/// 
/// # Arguments
/// * `scalar` - The scalar field element
/// * `window_idx` - Window index (0 = least significant window)
/// * `c` - Window size in bits
/// * `scalar_bits` - Total bits in scalar (unused, kept for API compatibility)
/// 
/// # Returns
/// Bucket index (0 to 2^c - 1) extracted from the scalar
fn extract_window_bits<F: PrimeField>(
    scalar: &F,
    window_idx: usize,
    c: usize,
    _scalar_bits: usize,
) -> usize {
    // Convert scalar to little-endian bytes (more natural for bit extraction)
    let scalar_bigint = scalar.into_bigint();
    let bytes = scalar_bigint.to_bytes_le();
    
    // Calculate bit position: window_idx * c gives start bit (LSB = 0)
    let start_bit = window_idx * c;
    
    // Extract c bits starting from start_bit (little-endian bit order)
    let mut result = 0usize;
    for i in 0..c {
        let bit_pos = start_bit + i;
        let byte_idx = bit_pos / 8;
        let bit_in_byte = bit_pos % 8;  // LSB = bit 0
        
        if byte_idx < bytes.len() {
            let bit = (bytes[byte_idx] >> bit_in_byte) & 1;
            result |= (bit as usize) << i;
        }
    }
    
    result
}

/// Combine buckets using running sum technique
/// 
/// Compute: Σ i * buckets[i] for i = 1 to 2^c - 1
/// 
/// Optimization: Use running sum
/// running_sum[i] = Σ_{j=i}^{2^c-1} buckets[j]
/// result = Σ running_sum[i]
fn combine_buckets<G: CurveGroup>(buckets: &[G]) -> G {
    let mut running_sum = G::zero();
    let mut result = G::zero();
    
    // Process from highest index to lowest (skip bucket 0)
    for i in (1..buckets.len()).rev() {
        running_sum += buckets[i];
        result += running_sum;
    }
    
    result
}

/// Determine optimal window size c based on input size n
/// 
/// Theoretical optimum: c ≈ log2(n)
/// Practical considerations:
/// - Smaller c: fewer buckets, more iterations
/// - Larger c: more buckets (memory), fewer iterations
/// 
/// Trade-off analysis:
/// - Bucket count: 2^c
/// - Iterations: ⌈bits/c⌉
/// - Total work: n * ⌈bits/c⌉ + 2^c * ⌈bits/c⌉
fn optimal_window_size(n: usize) -> usize {
    if n < 32 {
        return 1;
    } else if n < 128 {
        return 2;
    } else if n < 512 {
        return 3;
    } else if n < 2048 {
        return 4;
    } else if n < 8192 {
        return 5;
    } else if n < 32768 {
        return 6;
    } else if n < 131072 {
        return 7;
    } else {
        return 8;  // Cap at 8 (256 buckets max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{G1Projective, Fr};
    use ark_std::{test_rng, UniformRand, Zero};
    
    #[test]
    fn test_msm_empty() {
        let points: Vec<G1Projective> = vec![];
        let scalars: Vec<Fr> = vec![];
        let result = msm(&points, &scalars);
        assert_eq!(result, G1Projective::zero());
    }
    
    #[test]
    fn test_msm_single() {
        let mut rng = test_rng();
        let point = G1Projective::rand(&mut rng);
        let scalar = Fr::rand(&mut rng);
        
        let result = msm(&[point], &[scalar]);
        let expected = point * scalar;
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_msm_vs_naive() {
        let mut rng = test_rng();
        let n = 100;
        
        let points: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let result_pippenger = msm(&points, &scalars);
        let result_naive = msm_naive(&points, &scalars);
        
        assert_eq!(result_pippenger, result_naive);
    }
    
    #[test]
    fn test_msm_linearity() {
        let mut rng = test_rng();
        let n = 50;
        
        let points: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars_a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let scalars_b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // MSM(points, a + b) = MSM(points, a) + MSM(points, b)
        let scalars_sum: Vec<Fr> = scalars_a.iter().zip(scalars_b.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        
        let result_sum = msm(&points, &scalars_sum);
        let result_a = msm(&points, &scalars_a);
        let result_b = msm(&points, &scalars_b);
        let result_separate = result_a + result_b;
        
        assert_eq!(result_sum, result_separate);
    }
    
    #[test]
    fn test_extract_window_bits() {
        // Test with Fr::from(255) = 0b11111111
        let scalar = Fr::from(255u64);
        let bits = 255;  // BLS12-381 Fr has 255 bits
        
        // Extract first 4 bits (LSB)
        let window0 = extract_window_bits(&scalar, 0, 4, bits);
        assert_eq!(window0, 0b1111);  // Lower 4 bits = 15
        
        // Extract next 4 bits
        let window1 = extract_window_bits(&scalar, 1, 4, bits);
        assert_eq!(window1, 0b1111);  // Next 4 bits = 15
    }
    
    #[test]
    fn test_combine_buckets() {
        let mut rng = test_rng();
        let c = 3;  // 8 buckets
        let num_buckets = 1 << c;
        
        let buckets: Vec<G1Projective> = (0..num_buckets)
            .map(|_| G1Projective::rand(&mut rng))
            .collect();
        
        let result = combine_buckets(&buckets);
        
        // Verify: result = Σ i * buckets[i]
        let mut expected = G1Projective::zero();
        for i in 1..num_buckets {
            expected += buckets[i] * Fr::from(i as u64);
        }
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_optimal_window_size() {
        // Verify window size increases with n (roughly log2(n))
        assert_eq!(optimal_window_size(16), 1);
        assert_eq!(optimal_window_size(100), 2);
        assert_eq!(optimal_window_size(500), 3);
        assert_eq!(optimal_window_size(1000), 4);
        assert_eq!(optimal_window_size(10000), 6);  // Corrected
        assert_eq!(optimal_window_size(100000), 7);
        assert_eq!(optimal_window_size(1000000), 8);
        
        // Verify it's monotonically increasing
        let mut prev_c = 0;
        for n_exp in 1..20 {
            let n = 1 << n_exp;  // 2^n_exp
            let c = optimal_window_size(n);
            assert!(c >= prev_c, "window size should be monotonic");
            prev_c = c;
        }
    }
    
    #[test]
    fn test_msm_large() {
        let mut rng = test_rng();
        let n = 1024;
        
        let points: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let result_pippenger = msm(&points, &scalars);
        let result_naive = msm_naive(&points, &scalars);
        
        assert_eq!(result_pippenger, result_naive);
    }
    
    #[test]
    fn test_msm_affine_vs_projective() {
        let mut rng = test_rng();
        let n = 128;
        
        let points: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Test affine sequential
        let result_affine_seq = msm_pippenger_affine_sequential(&points, &scalars);
        let result_naive = msm_naive(&points, &scalars);
        
        assert_eq!(result_affine_seq, result_naive, "Affine sequential should match naive");
    }
    
    #[test]
    fn test_msm_affine_parallel() {
        let mut rng = test_rng();
        let n = 512;
        
        let points: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Test affine parallel
        let result_affine_par = msm_pippenger_affine_parallel(&points, &scalars);
        let result_naive = msm_naive(&points, &scalars);
        
        assert_eq!(result_affine_par, result_naive, "Affine parallel should match naive");
    }
}

