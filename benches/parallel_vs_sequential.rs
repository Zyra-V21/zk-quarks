use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks::field::Bls12381Fr as Fr;
use quarks::polynomial::{MultilinearPolynomial, SparseMultilinearPolynomial};
use quarks::r1cs::SparseMatrix;
use ark_std::test_rng;
use rand::Rng;

/// Benchmark MLE evaluation: measures benefit of parallelization
fn bench_mle_evaluation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("mle_parallel_scaling");
    
    for num_vars in [10, 12, 14, 16].iter() {
        let size = 1usize << num_vars;
        let mut rng = test_rng();
        let evals: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let poly = MultilinearPolynomial::from_evaluations(evals, *num_vars);
        let x: Vec<Fr> = (0..*num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("mle_eval", format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    black_box(poly.evaluate(black_box(&x)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark sparse MLE evaluation
fn bench_sparse_mle_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_mle_parallel_scaling");
    
    for (num_vars, sparsity) in [(10, 128), (12, 512), (14, 2048)].iter() {
        let mut rng = test_rng();
        let domain_size = 1usize << num_vars;
        
        // Create sparse polynomial with given sparsity
        let mut entries = Vec::new();
        for _ in 0..*sparsity {
            let idx = rng.gen::<usize>() % domain_size;
            let val = Fr::from(rng.gen::<u64>());
            entries.push((idx, val));
        }
        let sparse_poly = SparseMultilinearPolynomial::from_entries(entries, *num_vars);
        let x: Vec<Fr> = (0..*num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
        
        group.throughput(Throughput::Elements(*sparsity as u64));
        group.bench_with_input(
            BenchmarkId::new("sparse_eval", format!("ν={}_s={}", num_vars, sparsity)),
            &(num_vars, sparsity),
            |b, _| {
                b.iter(|| {
                    black_box(sparse_poly.evaluate(black_box(&x)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark sparse matrix-vector product
fn bench_sparse_matrix_mul_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_matrix_parallel_scaling");
    
    for n_exp in [10, 12, 14].iter() {
        let n = 1usize << n_exp;
        let mut rng = test_rng();
        
        // Create sparse matrix with ~10n entries
        let mut matrix = SparseMatrix::new(n, n);
        for _ in 0..(10 * n) {
            let r = rng.gen::<usize>() % n;
            let c = rng.gen::<usize>() % n;
            let v = Fr::from(rng.gen::<u64>());
            matrix.add_entry(r, c, v);
        }
        
        let vector: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u64>())).collect();
        
        group.throughput(Throughput::Elements((10 * n) as u64));
        group.bench_with_input(
            BenchmarkId::new("matrix_mul", format!("n=2^{}", n_exp)),
            n_exp,
            |b, _| {
                b.iter(|| {
                    black_box(matrix.mul_vector(black_box(&vector)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark Hadamard product
fn bench_hadamard_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("hadamard_parallel_scaling");
    
    for n_exp in [10, 12, 14, 16].iter() {
        let n = 1usize << n_exp;
        let mut rng = test_rng();
        let a: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u64>())).collect();
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::new("hadamard", format!("n=2^{}", n_exp)),
            n_exp,
            |b_bench, _| {
                b_bench.iter(|| {
                    black_box(SparseMatrix::hadamard(black_box(&a), black_box(&b)))
                });
            },
        );
    }
    group.finish();
}

/// End-to-end comparison: measures total speedup
fn bench_end_to_end_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_end_to_end");
    
    // Simulate a sum-check-like workload
    for num_vars in [10, 12, 14].iter() {
        let size = 1usize << num_vars;
        let mut rng = test_rng();
        
        let evals1: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let evals2: Vec<Fr> = (0..size).map(|_| Fr::from(rng.gen::<u64>())).collect();
        let poly1 = MultilinearPolynomial::from_evaluations(evals1, *num_vars);
        let poly2 = MultilinearPolynomial::from_evaluations(evals2, *num_vars);
        
        let x: Vec<Fr> = (0..*num_vars).map(|_| Fr::from(rng.gen::<u64>())).collect();
        
        group.throughput(Throughput::Elements((2 * size) as u64));
        group.bench_with_input(
            BenchmarkId::new("sumcheck_round", format!("ν={}", num_vars)),
            num_vars,
            |b, _| {
                b.iter(|| {
                    // Simulate two polynomial evaluations + Hadamard product
                    let v1 = poly1.evaluate(black_box(&x));
                    let v2 = poly2.evaluate(black_box(&x));
                    black_box(v1 * v2)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_mle_evaluation_scaling,
    bench_sparse_mle_scaling,
    bench_sparse_matrix_mul_scaling,
    bench_hadamard_scaling,
    bench_end_to_end_comparison
);
criterion_main!(benches);

