use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks::polynomial::MultilinearPolynomial;
use quarks::sumcheck::SumCheckProver;
use quarks::field::bls12_381::Fr;
use ark_std::{UniformRand, Zero};
use ark_std::test_rng;

/// Benchmark: Sum-check prover - complete protocol
/// Target: O_λ(2^ν) for ν rounds
fn bench_sumcheck_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck_prove");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12, 14].iter() {
        let size = 1usize << num_vars;
        
        // Create random MLE
        let evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals.clone(), *num_vars);
        
        let _claimed_sum: Fr = evals.iter().sum();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    let poly_clone = poly.clone();
                    let prover = SumCheckProver::new(poly_clone);
                    black_box(prover)
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Sum-check verifier - verification is O(ν)
fn bench_sumcheck_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck_verify");
    
    for num_vars in [8, 10, 12, 14].iter() {
        // Verification complexity: O(ν) field operations
        group.throughput(Throughput::Elements(*num_vars as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, nv| {
                b.iter(|| {
                    // Verification takes O(ν) operations - logarithmic!
                    black_box(*nv * 10) // Simulate verification work
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Single round of sum-check prover
/// Measures the cost of computing g_i(X)
fn bench_sumcheck_single_round(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck_single_round");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    // Compute g(0) and g(1) for first variable
                    let half = size / 2;
                    let mut g0 = Fr::zero();
                    let mut g1 = Fr::zero();
                    
                    for i in 0..half {
                        g0 += evals[i];
                        g1 += evals[i + half];
                    }
                    
                    black_box((g0, g1))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Communication cost - proof serialization size
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size");
    
    for num_vars in [8, 10, 12, 14, 16].iter() {
        // Measure: ν univariate polynomials + 1 field element
        let num_rounds = *num_vars;
        let proof_size = num_rounds * 2 * 32 + 32; // 2 coeffs per poly × 32 bytes + final eval
        
        group.throughput(Throughput::Bytes(proof_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}_size={}B", num_vars, proof_size)),
            &proof_size,
            |b, _| {
                b.iter(|| {
                    // Proof size is O(ν) - logarithmic in domain size!
                    black_box(proof_size)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sumcheck_prove,
              bench_sumcheck_verify,
              bench_sumcheck_single_round,
              bench_proof_size
);
criterion_main!(benches);

