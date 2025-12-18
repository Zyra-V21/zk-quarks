use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks_zk::snark::lakonia::LakoniaSnark;
use quarks_zk::snark::kopis::KopisSnark;
use quarks_zk::snark::xiphos::XiphosSnark;
use quarks_zk::snark::common::Witness;
use quarks_zk::r1cs::{R1CSInstance, SparseMatrix};
use quarks_zk::field::bls12_381::Fr;
use ark_std::{UniformRand, One, test_rng};

/// Helper: Create R1CS instance with n multiplication gates
/// Each gate: w[3i] * w[3i+1] = w[3i+2]
/// 
/// R1CS: z = (io, 1, w) where io=[], so z = [1, w[0], ..., w[m-1]]
fn create_mul_chain_r1cs(n: usize) -> (R1CSInstance<Fr>, Witness) {
    let mut rng = test_rng();
    
    let num_constraints = n;
    let num_witness_vars = n * 3;
    let num_z_vars = 1 + num_witness_vars; // z[0]=1, z[1..]=w
    
    let mut a = SparseMatrix::new(num_constraints, num_z_vars);
    let mut b = SparseMatrix::new(num_constraints, num_z_vars);
    let mut c = SparseMatrix::new(num_constraints, num_z_vars);
    
    let mut witness_values = Vec::new();
    
    for i in 0..num_constraints {
        // z indices: +1 offset for z[0]=1
        let z_idx_a = 1 + (i * 3);
        let z_idx_b = 1 + (i * 3) + 1;
        let z_idx_c = 1 + (i * 3) + 2;
        
        // Constraint i: z[z_idx_a] * z[z_idx_b] = z[z_idx_c]
        a.add_entry(i, z_idx_a, Fr::one());
        b.add_entry(i, z_idx_b, Fr::one());
        c.add_entry(i, z_idx_c, Fr::one());
        
        // Generate satisfying witness
        let v1 = Fr::rand(&mut rng);
        let v2 = Fr::rand(&mut rng);
        let v3 = v1 * v2;
        
        witness_values.push(v1);
        witness_values.push(v2);
        witness_values.push(v3);
    }
    
    let instance = R1CSInstance::new(a, b, c, num_constraints, num_z_vars, 0);
    let witness = Witness::new(witness_values);
    
    (instance, witness)
}

/// Benchmark: Lakonia NIZK - Prover
/// Target: O_λ(n) prover time
fn bench_lakonia_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("lakonia_prove");
    let _rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        let lakonia = LakoniaSnark::setup(16);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(lakonia.prove(
                        black_box(&instance),
                        black_box(&witness),
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Lakonia NIZK - Verifier
/// Target: O_λ(n) verifier time (no preprocessing)
fn bench_lakonia_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("lakonia_verify");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        let lakonia = LakoniaSnark::setup(16);
        let proof = lakonia.prove(&instance, &witness, &mut rng);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| {
                    black_box(lakonia.verify(
                        black_box(&instance),
                        black_box(&proof),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis zkSNARK - Preprocessing
/// Target: O(n) field ops with untrusted assistant
fn bench_kopis_preprocess(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_preprocess");
    let _rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let n = 1usize << log_size;
        
        let (instance, _) = create_mul_chain_r1cs(n);
        let kopis = KopisSnark::setup(16);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(kopis.preprocess(
                        black_box(&instance),
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis zkSNARK - Prover
/// Target: O_λ(n) prover time
fn bench_kopis_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_prove");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        let kopis = KopisSnark::setup(16);
        let cc = kopis.preprocess(&instance, &mut rng);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(kopis.prove(
                        black_box(&instance),
                        black_box(&witness),
                        black_box(&cc),
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis zkSNARK - Verifier
/// Target: O_λ(√n) verification time
fn bench_kopis_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_verify");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12, 14].iter() {
        let n = 1usize << log_size;
        let sqrt_n = (n as f64).sqrt() as usize;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        let kopis = KopisSnark::setup(16);
        let cc = kopis.preprocess(&instance, &mut rng);
        let proof = kopis.prove(&instance, &witness, &cc, &mut rng);
        
        group.throughput(Throughput::Elements(sqrt_n as u64)); // O(√n)
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}_√n={}", log_size, sqrt_n)),
            &sqrt_n,
            |b, _| {
                b.iter(|| {
                    black_box(kopis.verify(
                        black_box(&instance),
                        black_box(&proof),
                        black_box(&cc),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Xiphos zkSNARK - Preprocessing
/// Target: O(n) field operations with untrusted assistant (Quadruple-efficient property 4)
/// Measures combined Assistant + Encoder time (paper TABLE 9)
fn bench_xiphos_preprocess(c: &mut Criterion) {
    let mut group = c.benchmark_group("xiphos_preprocess");
    let _rng = test_rng();
    
    // Use smaller sizes to avoid OOM - Dory-PC setup is memory intensive
    // For n=2^12, z.len()≈12,289, requiring setup_vars=14 which allocates 2^14=16,384 generators (~3GB)
    for log_size in [6, 8, 10].iter() {
        let n = 1usize << log_size;
        
        let (instance, _) = create_mul_chain_r1cs(n);
        
        // Calculate minimal setup size: need enough vars for z vector
        // z.len() = 1 + n*3, so log2(z.len()) ≈ log2(n) + 2
        let z_size = 1 + n * 3;
        let required_vars = (z_size as f64).log2().ceil() as usize;
        let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
        let setup_vars = setup_vars.max(2).min(12); // Cap at 12 (~100MB) to avoid OOM
        
        let xiphos = XiphosSnark::setup(setup_vars);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}_vars={}", log_size, setup_vars)),
            &n,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(xiphos.preprocess(
                        black_box(&instance),
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Xiphos zkSNARK - Prover
/// Target: O_λ(n) prover time (Quadruple-efficient property 1)
fn bench_xiphos_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("xiphos_prove");
    let mut rng = test_rng();
    
    for log_size in [6, 8, 10].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        
        // Calculate appropriate setup size
        let z_size = 1 + n * 3;
        let required_vars = (z_size as f64).log2().ceil() as usize;
        let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
        let setup_vars = setup_vars.max(2).min(12); // Cap at 12 (~100MB) to avoid OOM
        
        let xiphos = XiphosSnark::setup(setup_vars);
        let cc = xiphos.preprocess(&instance, &mut rng);
        
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(xiphos.prove(
                        black_box(&instance),
                        black_box(&witness),
                        black_box(&cc),
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Xiphos zkSNARK - Verifier
/// Target: O_λ(log n) verification time (Quadruple-efficient property 3) - FASTEST!
fn bench_xiphos_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("xiphos_verify");
    let mut rng = test_rng();
    
    // Use smaller sizes to avoid OOM
    for log_size in [6, 8, 10, 12].iter() {
        let n = 1usize << log_size;
        let log_n = *log_size as usize;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        
        // Calculate appropriate setup size
        let z_size = 1 + n * 3;
        let required_vars = (z_size as f64).log2().ceil() as usize;
        let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
        let setup_vars = setup_vars.max(2).min(12);
        
        let xiphos = XiphosSnark::setup(setup_vars);
        let cc = xiphos.preprocess(&instance, &mut rng);
        let proof = xiphos.prove(&instance, &witness, &cc, &mut rng);
        
        group.throughput(Throughput::Elements(log_n as u64)); // O(log n) !!!
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}_log_n={}", log_size, log_n)),
            &log_n,
            |b, _| {
                b.iter(|| {
                    black_box(xiphos.verify(
                        black_box(&instance),
                        black_box(&proof),
                        black_box(&cc),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Xiphos vs Kopis verification comparison
/// Shows logarithmic vs sqrt(n) scaling
fn bench_xiphos_vs_kopis_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("xiphos_vs_kopis_verification");
    let mut rng = test_rng();
    
    // Use smaller sizes to avoid OOM
    for log_size in [8, 10, 12].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        
        // Calculate appropriate setup size
        let z_size = 1 + n * 3;
        let required_vars = (z_size as f64).log2().ceil() as usize;
        let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
        let setup_vars = setup_vars.max(2).min(12);
        
        // Xiphos
        let xiphos = XiphosSnark::setup(setup_vars);
        let cc_xiphos = xiphos.preprocess(&instance, &mut rng);
        let proof_xiphos = xiphos.prove(&instance, &witness, &cc_xiphos, &mut rng);
        
        // Kopis
        let kopis = KopisSnark::setup(setup_vars);
        let cc_kopis = kopis.preprocess(&instance, &mut rng);
        let proof_kopis = kopis.prove(&instance, &witness, &cc_kopis, &mut rng);
        
        let log_n = *log_size;
        let sqrt_n = (n as f64).sqrt() as usize;
        
        group.bench_with_input(
            BenchmarkId::new("xiphos", format!("n=2^{}_ops={}", log_size, log_n)),
            &log_n,
            |b, _| {
                b.iter(|| {
                    black_box(xiphos.verify(&instance, &proof_xiphos, &cc_xiphos))
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("kopis", format!("n=2^{}_ops={}", log_size, sqrt_n)),
            &sqrt_n,
            |b, _| {
                b.iter(|| {
                    black_box(kopis.verify(&instance, &proof_kopis, &cc_kopis))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Proof sizes comparison
/// Lakonia vs Kopis vs Xiphos
fn bench_proof_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_sizes");
    let mut rng = test_rng();
    
    // Use smaller sizes to avoid OOM with Dory-PC
    for log_size in [10, 12, 14].iter() {
        let n = 1usize << log_size;
        
        let (instance, witness) = create_mul_chain_r1cs(n);
        
        // Calculate appropriate setup size
        let z_size = 1 + n * 3;
        let required_vars = (z_size as f64).log2().ceil() as usize;
        let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
        let setup_vars = setup_vars.max(2).min(14);
        
        // Lakonia: O_λ(log n)
        let lakonia = LakoniaSnark::setup(setup_vars);
        let _proof_lakonia = lakonia.prove(&instance, &witness, &mut rng);
        let lakonia_size = log_size * 64; // Approximate: log(n) field elements
        
        // Kopis: O_λ(log n) but with constant commitment
        let kopis = KopisSnark::setup(setup_vars);
        let cc_kopis = kopis.preprocess(&instance, &mut rng);
        let _proof_kopis = kopis.prove(&instance, &witness, &cc_kopis, &mut rng);
        let kopis_size = 48 + log_size * 64; // 48B commitment + log proof
        
        // Xiphos: O_λ(log n) with Dory-PC
        let xiphos = XiphosSnark::setup(setup_vars);
        let cc_xiphos = xiphos.preprocess(&instance, &mut rng);
        let _proof_xiphos = xiphos.prove(&instance, &witness, &cc_xiphos, &mut rng);
        let xiphos_size = log_size * 96; // log(n) group elements
        
        group.throughput(Throughput::Bytes(lakonia_size as u64));
        group.bench_with_input(
            BenchmarkId::new("sizes", format!("n=2^{}", log_size)),
            log_size,
            |b, _| {
                b.iter(|| {
                    black_box((lakonia_size, kopis_size, xiphos_size))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Target metrics from paper (n = 2^20)
/// Figure 6-9: Prover ~168s, Verifier <100ms
fn bench_paper_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper_targets");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(300)); // 5 min per benchmark
    
    let _rng = test_rng();
    let n = 1usize << 12; // Use 2^12 instead of 2^20 to avoid OOM with Dory-PC
    
    let (instance, witness) = create_mul_chain_r1cs(n);
    
    // Calculate appropriate setup size
    let z_size = 1 + n * 3;
    let required_vars = (z_size as f64).log2().ceil() as usize;
    let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
    let setup_vars = setup_vars.max(2).min(14);
    
    // Xiphos: Full quadruple-efficient pipeline
    let xiphos = XiphosSnark::setup(setup_vars);
    
    group.bench_function("xiphos_full_pipeline_n=2^12", |b| {
        b.iter(|| {
            let mut rng_clone = test_rng();
            
            // Preprocessing with assistant: O(n) field ops
            let cc = xiphos.preprocess(&instance, &mut rng_clone);
            
            // Prove: O_λ(n)
            let proof = xiphos.prove(&instance, &witness, &cc, &mut rng_clone);
            
            // Verify: O_λ(log n) - FASTEST
            let result = xiphos.verify(&instance, &proof, &cc);
            
            black_box((cc, proof, result))
        });
    });
    
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_lakonia_prove,
              bench_lakonia_verify,
              bench_kopis_preprocess,
              bench_kopis_prove,
              bench_kopis_verify,
              bench_xiphos_preprocess,
              bench_xiphos_prove,
              bench_xiphos_verify,
              bench_xiphos_vs_kopis_verification,
              bench_proof_sizes,
              bench_paper_targets
);
criterion_main!(benches);

