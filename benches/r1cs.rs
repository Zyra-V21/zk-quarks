use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks::r1cs::{R1CSInstance, Witness, SparseMatrix};
use quarks::field::bls12_381::Fr;
use ark_std::{test_rng, UniformRand};

/// Benchmark: R1CS constraint satisfaction checking
/// Target: O(m + n) where m = constraints, n = vars
fn bench_r1cs_is_satisfied(c: &mut Criterion) {
    let mut group = c.benchmark_group("r1cs_is_satisfied");
    let mut rng = test_rng();
    
    // Test sizes: 2^8, 2^10, 2^12, 2^14
    for log_size in [8, 10, 12, 14].iter() {
        let size = 1usize << log_size;
        let num_constraints = size;
        let num_vars = size;
        
        // Create R1CS instance: A·z ∘ B·z = C·z
        let mut a = SparseMatrix::new(num_constraints, num_vars);
        let mut b = SparseMatrix::new(num_constraints, num_vars);
        let mut c = SparseMatrix::new(num_constraints, num_vars);
        
        // Fill with random sparse entries (10% density)
        let density = size / 10;
        for i in 0..num_constraints {
            for _ in 0..density.min(num_vars) {
                let col = i % num_vars;
                a.add_entry(i, col, Fr::rand(&mut rng));
                b.add_entry(i, (col + 1) % num_vars, Fr::rand(&mut rng));
                c.add_entry(i, (col + 2) % num_vars, Fr::rand(&mut rng));
            }
        }
        
        let instance = R1CSInstance::new(a, b, c, num_constraints, num_vars, 0);
        
        // Create witness
        let assignments = (0..num_vars).map(|_| Fr::rand(&mut rng)).collect();
        let witness = Witness {
            public_inputs: vec![],
            assignments,
        };
        
        group.throughput(Throughput::Elements(num_constraints as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(instance.is_satisfied(black_box(&witness)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Sparse matrix-vector multiplication
/// Core operation in R1CS
fn bench_sparse_matrix_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_matrix_mul");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12, 14].iter() {
        let size = 1usize << log_size;
        
        let mut matrix = SparseMatrix::new(size, size);
        
        // 10% density
        let entries_per_row = size / 10;
        for i in 0..size {
            for j in 0..entries_per_row {
                let col = (i + j) % size;
                matrix.add_entry(i, col, Fr::rand(&mut rng));
            }
        }
        
        let vector: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(matrix.mul_vector(black_box(&vector)))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Hadamard (element-wise) product
fn bench_hadamard_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("hadamard_product");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12, 14].iter() {
        let size = 1usize << log_size;
        
        let v1: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let v2: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let result: Vec<Fr> = v1.iter()
                        .zip(v2.iter())
                        .map(|(a, b)| *a * *b)
                        .collect();
                    black_box(result)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_r1cs_is_satisfied, bench_sparse_matrix_mul, bench_hadamard_product
);
criterion_main!(benches);

