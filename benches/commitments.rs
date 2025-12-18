use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quarks_zk::commitments::pedersen::PedersenParams;
use quarks_zk::commitments::ipp::{IppParams, IppProver, IppVerifier, IppTranscript};
use quarks_zk::commitments::bipp::{BippParams, BippProver, BippVerifier, BippTranscript};
use quarks_zk::field::bls12_381::Fr;
use ark_std::{UniformRand, test_rng};

/// Benchmark: Pedersen commitment
/// Target: O(n) scalar multiplications
fn bench_pedersen_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen_commit");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let size = 1usize << log_size;
        
        let params = PedersenParams::new();
        let values: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(params.commit_vector(black_box(&values), &mut rng_clone))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: IPP (Inner Product Proof) - Prover
/// Target: O(n) initially, then O(log n) recursive steps
fn bench_ipp_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipp_prove");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let size = 1usize << log_size;
        
        let params = IppParams::new(size);
        let a: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            &size,
            |bench, _| {
                bench.iter(|| {
                    let mut transcript = IppTranscript::new(b"ipp_bench");
                    let mut rng_clone = test_rng();
                    black_box(IppProver::prove(
                        black_box(&params),
                        black_box(&a),
                        black_box(&b),
                        &mut transcript,
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: IPP Verifier
/// Target: O(log n) - logarithmic verification!
fn bench_ipp_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipp_verify");
    let mut rng = test_rng();
    
    for log_size in [8, 10, 12].iter() {
        let size = 1usize << log_size;
        
        let params = IppParams::new(size);
        let a: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        let _y: Fr = a.iter().zip(b.iter()).map(|(ai, bi)| *ai * bi).sum();
        let commitment = params.commit(&a, &b);
        
        let mut transcript = IppTranscript::new(b"ipp_bench");
        let proof = IppProver::prove(&params, &a, &b, &mut transcript, &mut rng);
        
        group.throughput(Throughput::Elements(*log_size as u64)); // O(log n)
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("n=2^{}", log_size)),
            log_size,
            |bench, _| {
                bench.iter(|| {
                    let mut transcript_verify = IppTranscript::new(b"ipp_bench");
                    black_box(IppVerifier::verify(
                        &params,
                        &commitment,
                        &proof,
                        &mut transcript_verify,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: BIPP (Bilinear IPP) - Prover
/// Target: O(s) with s = vector size, using pairings
fn bench_bipp_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("bipp_prove");
    let mut rng = test_rng();
    
    for log_size in [4, 6, 8].iter() { // Smaller sizes due to pairing cost
        let size = 1usize << log_size;
        
        let params = BippParams::new(size);
        let v: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        // Generate G1 elements for z
        use ark_ec::Group;
        use ark_bls12_381::G1Projective;
        let z: Vec<G1Projective> = (0..size)
            .map(|_| G1Projective::generator() * Fr::rand(&mut rng))
            .collect();
        
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("s=2^{}", log_size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut transcript = BippTranscript::new(b"bipp_bench");
                    let mut rng_clone = test_rng();
                    black_box(BippProver::prove(
                        black_box(&params),
                        black_box(&z),
                        black_box(&v),
                        &mut transcript,
                        &mut rng_clone,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: BIPP Verifier
/// Target: O(log s) pairings
fn bench_bipp_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bipp_verify");
    let mut rng = test_rng();
    
    for log_size in [4, 6, 8].iter() {
        let size = 1usize << log_size;
        
        let params = BippParams::new(size);
        let v: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        
        use ark_ec::Group;
        use ark_bls12_381::G1Projective;
        let z: Vec<G1Projective> = (0..size)
            .map(|_| G1Projective::generator() * Fr::rand(&mut rng))
            .collect();
        
        // Compute commitment using params
        let commitment = params.commit(&z, &v);
        
        let mut transcript = BippTranscript::new(b"bipp_bench");
        let proof = BippProver::prove(&params, &z, &v, &mut transcript, &mut rng);
        
        // y is the bilinear inner product result (GT element)
        let _y = commitment; // The commitment IS the result for BIPP
        
        group.throughput(Throughput::Elements(*log_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("s=2^{}", log_size)),
            log_size,
            |bench, _| {
                bench.iter(|| {
                    let mut transcript_verify = BippTranscript::new(b"bipp_bench");
                    black_box(BippVerifier::verify(
                        &params,
                        &commitment,
                        &proof,
                        &mut transcript_verify,
                    ))
                });
            },
        );
    }
    group.finish();
}

/// Benchmark: Pedersen homomorphic addition
/// Used in ZK proofs for combining commitments
fn bench_pedersen_homomorphic_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen_homomorphic_add");
    let mut rng = test_rng();
    
    let params = PedersenParams::new();
    
    group.bench_function("add_commitments", |b| {
        let val1 = Fr::rand(&mut rng);
        let val2 = Fr::rand(&mut rng);
        let blind1 = Fr::rand(&mut rng);
        let blind2 = Fr::rand(&mut rng);
        
        let comm1 = params.commit_with_blinding(&val1, &blind1);
        let comm2 = params.commit_with_blinding(&val2, &blind2);
        
        b.iter(|| {
            black_box(comm1.point + comm2.point)
        });
    });
    
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pedersen_commit,
              bench_ipp_prove,
              bench_ipp_verify,
              bench_bipp_prove,
              bench_bipp_verify,
              bench_pedersen_homomorphic_add
);
criterion_main!(benches);

