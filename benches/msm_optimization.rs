//! Benchmark: MSM optimization (Pippenger vs Naive)
//!
//! Compares naive O(n) scalar multiplication vs Pippenger's O(n/log n)

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use quarks::utils::msm::msm;
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use ark_std::{test_rng, Zero};

/// Naive MSM for comparison
fn msm_naive(points: &[G1Projective], scalars: &[Fr]) -> G1Projective {
    let mut result = G1Projective::zero();
    for (p, s) in points.iter().zip(scalars.iter()) {
        result = result + *p * s;
    }
    result
}

fn bench_msm_vs_naive(c: &mut Criterion) {
    let mut group = c.benchmark_group("msm_comparison");
    
    // Test different sizes
    for &exp in &[6, 8, 10, 12] {
        let n = 1 << exp;  // 64, 256, 1024, 4096
        
        let mut rng = test_rng();
        let points: Vec<G1Projective> = (0..n)
            .map(|_| G1Projective::rand(&mut rng))
            .collect();
        let scalars: Vec<Fr> = (0..n)
            .map(|_| Fr::rand(&mut rng))
            .collect();
        
        // Benchmark naive MSM
        group.bench_with_input(
            BenchmarkId::new("naive", n),
            &n,
            |b, _| {
                b.iter(|| {
                    black_box(msm_naive(&points, &scalars))
                });
            },
        );
        
        // Benchmark Pippenger MSM (auto-selects affine for n >= 64)
        group.bench_with_input(
            BenchmarkId::new("pippenger_affine", n),
            &n,
            |b, _| {
                b.iter(|| {
                    black_box(msm(&points, &scalars))
                });
            },
        );
    }
    
    group.finish();
}

fn bench_commitment_operations(c: &mut Criterion) {
    use quarks::commitments::pedersen::PedersenParams;
    use quarks::commitments::ipp::IppParams;
    use quarks::commitments::bipp::bilinear_inner_product;
    
    let mut group = c.benchmark_group("commitment_msm_impact");
    
    for &exp in &[6, 8, 10] {
        let n = 1 << exp;
        let mut rng = test_rng();
        
        // Pedersen vector commit
        let pedersen = PedersenParams::new();
        let values: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let blinding = Fr::rand(&mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("pedersen_vector", n),
            &n,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(pedersen.commit_vector_with_blinding(&values, &blinding))
                });
            },
        );
        
        // IPP commit
        let ipp_params = IppParams::new(n);
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        group.bench_with_input(
            BenchmarkId::new("ipp_commit", n),
            &n,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(ipp_params.commit(&a, &b_vec))
                });
            },
        );
        
        // BIPP inner product
        let z: Vec<G1Projective> = (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
        let v: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        group.bench_with_input(
            BenchmarkId::new("bipp_inner_product", n),
            &n,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(bilinear_inner_product(&z, &v))
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_msm_vs_naive, bench_commitment_operations
);
criterion_main!(benches);

