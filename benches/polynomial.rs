use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks_zk::polynomial::{MultilinearPolynomial, SparseMultilinearPolynomial, eq_polynomial};
use quarks_zk::field::bls12_381::Fr;
use ark_std::{UniformRand, Zero};
use ark_std::test_rng;

/// Benchmark: Multilinear polynomial evaluation
/// Target: O(2^ν) for ν variables
fn bench_mle_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mle_evaluation");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12, 14].iter() {
        let size = 1usize << num_vars;
        
        // Create random MLE
        let evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, *num_vars);
        
        // Random evaluation point
        let point: Vec<Fr> = (0..*num_vars).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    black_box(poly.evaluate(black_box(&point)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Sparse MLE evaluation
/// Target: O(|S|·ν) where |S| = support size
fn bench_sparse_mle_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_mle_evaluation");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12, 14].iter() {
        let size = 1usize << num_vars;
        
        // Create sparse MLE with 1% density
        let support_size = size / 100;
        let mut entries = Vec::new();
        for i in 0..support_size {
            entries.push((i, Fr::rand(&mut rng)));
        }
        let poly = SparseMultilinearPolynomial::from_entries(entries, *num_vars);
        
        let point: Vec<Fr> = (0..*num_vars).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(support_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}_s={}", num_vars, support_size)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    black_box(poly.evaluate(black_box(&point)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Equality polynomial computation
/// eq(x, e) - used extensively in sum-check
fn bench_eq_polynomial(c: &mut Criterion) {
    let mut group = c.benchmark_group("eq_polynomial");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let point: Vec<Fr> = (0..*num_vars).map(|_| Fr::rand(&mut rng)).collect();
        let e: Vec<bool> = (0..*num_vars).map(|i| i % 2 == 0).collect();
        
        group.throughput(Throughput::Elements((1usize << num_vars) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    black_box(eq_polynomial(black_box(&point), black_box(&e)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Polynomial binding (partial evaluation)
/// Used in sum-check protocol
fn bench_polynomial_bind(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_bind");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        let evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        let challenge = Fr::rand(&mut rng);
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    // Bind first variable: f(r, x₂, ..., xᵥ)
                    let bound_size = size / 2;
                    let mut bound_evals = vec![Fr::zero(); bound_size];
                    for i in 0..bound_size {
                        bound_evals[i] = evals[i] * (Fr::from(1u64) - challenge) 
                            + evals[i + bound_size] * challenge;
                    }
                    black_box(bound_evals)
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Dense to sparse conversion
fn bench_dense_to_sparse(c: &mut Criterion) {
    let mut group = c.benchmark_group("dense_to_sparse");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        
        // Create mostly-zero evaluations (1% nonzero)
        let mut evals = vec![Fr::zero(); size];
        for i in (0..size).step_by(100) {
            evals[i] = Fr::rand(&mut rng);
        }
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    let dense_poly = MultilinearPolynomial::from_evaluations(evals.clone(), *num_vars);
                    black_box(SparseMultilinearPolynomial::from_dense(&dense_poly))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mle_evaluation, 
              bench_sparse_mle_evaluation, 
              bench_eq_polynomial,
              bench_polynomial_bind,
              bench_dense_to_sparse
);
criterion_main!(benches);

