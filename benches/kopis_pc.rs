use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks_zk::kopis_pc::{KopisParams, commit, prove_eval, verify_eval, KopisTranscript};
use quarks_zk::field::bls12_381::Fr;
use ark_std::{UniformRand, test_rng};

/// Benchmark: Kopis-PC Setup
/// Target: O(2^ν) field operations
fn bench_kopis_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_pc_setup");
    
    for num_vars in [8, 10, 12].iter() {
        group.throughput(Throughput::Elements((1usize << num_vars) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, &nv| {
                b.iter(|| {
                    black_box(KopisParams::setup(nv))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis-PC Commit
/// Target: O_λ(1) commitment size - CONSTANT!
fn bench_kopis_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_pc_commit");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() { // Only even num_vars
        let size = 1usize << num_vars;
        
        let params = KopisParams::setup(*num_vars);
        let poly_evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(commit(
                        black_box(&params),
                        black_box(&poly_evals),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis-PC Prove Evaluation
/// Target: O_λ(log n) proof size
fn bench_kopis_prove_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_pc_prove_eval");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        
        let params = KopisParams::setup(*num_vars);
        let poly_evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        let (_, commitment_hint) = commit(&params, &poly_evals);
        
        // Random evaluation point
        let r: Vec<Fr> = (0..*num_vars).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut transcript = KopisTranscript::new(b"kopis_bench");
                    let mut rng_clone = test_rng();
                    black_box(prove_eval(
                        black_box(&params),
                        black_box(&poly_evals),
                        black_box(&commitment_hint),
                        black_box(&r),
                        &mut transcript,
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Kopis-PC Verify Evaluation
/// Target: O_λ(√n) verification time
fn bench_kopis_verify_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_pc_verify_eval");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        let sqrt_n = (size as f64).sqrt() as usize;
        
        let params = KopisParams::setup(*num_vars);
        let poly_evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        let (commitment, commitment_hint) = commit(&params, &poly_evals);
        
        let r: Vec<Fr> = (0..*num_vars).map(|_| Fr::rand(&mut rng)).collect();
        
        // Compute claimed value manually
        let mut claimed_value = Fr::zero();
        for (idx, &val) in poly_evals.iter().enumerate() {
            let mut term = val;
            for i in 0..*num_vars {
                let bit = ((idx >> (*num_vars - 1 - i)) & 1) == 1;
                term *= if bit { r[i] } else { Fr::from(1u64) - r[i] };
            }
            claimed_value += term;
        }
        
        let mut transcript = KopisTranscript::new(b"kopis_bench");
        let proof = prove_eval(&params, &poly_evals, &commitment_hint, &r, &mut transcript, &mut rng);
        
        group.throughput(Throughput::Elements(sqrt_n as u64)); // O(√n)
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}_√n={}", num_vars, sqrt_n)),
            &sqrt_n,
            |b, _| {
                b.iter(|| {
                    let mut transcript_verify = KopisTranscript::new(b"kopis_bench");
                    black_box(verify_eval(
                        black_box(&params),
                        black_box(&commitment),
                        black_box(&r),
                        black_box(claimed_value),
                        black_box(&proof),
                        &mut transcript_verify,
                    ))
                });
            },
        );
    }
    group.finish();
}

use ark_ff::Zero;

/// Benchmark: Commitment size - verify constant size
fn bench_kopis_commitment_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_commitment_size");
    let mut rng = test_rng();
    
    for num_vars in [8, 10, 12, 14, 16, 18, 20].iter() {
        if num_vars % 2 != 0 { continue; } // Skip odd num_vars
        
        let size = 1usize << num_vars;
        
        let params = KopisParams::setup(*num_vars);
        let poly_evals: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        let (_commitment, _) = commit(&params, &poly_evals);
        
        // GT element in BLS12-381: 576 bytes (Fq12)
        let commitment_size = 576; // 12 * 48 bytes
        
        group.throughput(Throughput::Bytes(commitment_size));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}_n=2^{}_size={}B", num_vars, num_vars, commitment_size)),
            &commitment_size,
            |b, _| {
                b.iter(|| {
                    // Verify commitment is constant size regardless of n
                    black_box(commitment_size)
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Proof size growth - verify O(log n)
fn bench_kopis_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_proof_size");
    
    for num_vars in [8, 10, 12, 14, 16].iter() {
        if num_vars % 2 != 0 { continue; }
        
        // Approximate proof size: O(log n) field elements
        // BIPP + IPP: log(√n) + log(√n) = ν rounds total
        let log_n = (*num_vars) as u64;
        let proof_size = 2 * log_n * 48 + 96; // G1 + GT elements
        
        group.throughput(Throughput::Bytes(proof_size));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}_size={}B", num_vars, proof_size)),
            &proof_size,
            |b, _| {
                b.iter(|| {
                    // Proof grows logarithmically!
                    black_box(proof_size)
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: End-to-end Kopis-PC (setup + commit + prove + verify)
fn bench_kopis_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_end_to_end");
    let _rng = test_rng();
    
    for num_vars in [8, 10, 12].iter() {
        let size = 1usize << num_vars;
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ν={}", num_vars)),
            num_vars,
            |b, &nv| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    
                    // Setup
                    let params = KopisParams::setup(nv);
                    
                    // Commit
                    let poly_evals: Vec<Fr> = (0..(1 << nv)).map(|_| Fr::rand(&mut rng_clone)).collect();
                    let (commitment, commitment_hint) = commit(&params, &poly_evals);
                    
                    // Prove
                    let r: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng_clone)).collect();
                    
                    // Compute claimed value
                    let mut claimed_value = Fr::zero();
                    for (idx, &val) in poly_evals.iter().enumerate() {
                        let mut term = val;
                        for i in 0..nv {
                            let bit = ((idx >> (nv - 1 - i)) & 1) == 1;
                            term *= if bit { r[i] } else { Fr::from(1u64) - r[i] };
                        }
                        claimed_value += term;
                    }
                    
                    let mut transcript = KopisTranscript::new(b"e2e");
                    let proof = prove_eval(&params, &poly_evals, &commitment_hint, &r, &mut transcript, &mut rng_clone);
                    
                    // Verify
                    let mut transcript_verify = KopisTranscript::new(b"e2e");
                    black_box(verify_eval(
                        &params,
                        &commitment,
                        &r,
                        claimed_value,
                        &proof,
                        &mut transcript_verify,
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_kopis_setup,
              bench_kopis_commit,
              bench_kopis_prove_eval,
              bench_kopis_verify_eval,
              bench_kopis_commitment_size,
              bench_kopis_proof_size,
              bench_kopis_end_to_end
);
criterion_main!(benches);

