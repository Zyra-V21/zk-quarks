//! Benchmark: Kopis-PC vs Dory-PC comparison
//!
//! Compares the two PCS implementations across all SNARKs:
//! - Setup time
//! - Commit time
//! - Prove time
//! - Verify time
//! - Proof size

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use quarks::{
    Lakonia, LakoniaDory,
    Kopis, KopisDory,
    Xiphos, XiphosKopis,
    Witness,
};
use quarks::r1cs::{R1CSInstance, SparseMatrix};
use ark_bls12_381::Fr;
use ark_std::{UniformRand, One, test_rng};

/// Create R1CS with n multiplication gates
fn create_mul_chain_r1cs(n: usize) -> (R1CSInstance<Fr>, Witness) {
    let mut rng = test_rng();
    
    let num_constraints = n;
    let num_witness_vars = n * 3;
    let num_z_vars = 1 + num_witness_vars;
    
    let mut a = SparseMatrix::new(num_constraints, num_z_vars);
    let mut b = SparseMatrix::new(num_constraints, num_z_vars);
    let mut c = SparseMatrix::new(num_constraints, num_z_vars);
    
    let mut witness_values = Vec::new();
    
    for i in 0..num_constraints {
        let z_idx_a = 1 + (i * 3);
        let z_idx_b = 1 + (i * 3) + 1;
        let z_idx_c = 1 + (i * 3) + 2;
        
        a.add_entry(i, z_idx_a, Fr::one());
        b.add_entry(i, z_idx_b, Fr::one());
        c.add_entry(i, z_idx_c, Fr::one());
        
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

/// Calculate setup vars for Lakonia (only needs z vector size)
fn calc_lakonia_vars(n: usize) -> usize {
    let z_size = 1 + n * 3;
    let required_vars = (z_size as f64).log2().ceil() as usize;
    let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
    setup_vars.max(4).min(14)
}

/// Calculate setup vars for Kopis/Xiphos (needs matrix commitment size in preprocess)
/// preprocess commits matrices of size: num_constraints.next_power_of_two() × num_z_vars.next_power_of_two()
fn calc_snark_vars(n: usize) -> usize {
    let num_constraints = n;
    let num_z_vars = 1 + n * 3;
    
    // Matrix size after padding (same as in snark/kopis.rs preprocess)
    let num_constraints_padded = num_constraints.next_power_of_two();
    let num_vars_padded = num_z_vars.next_power_of_two();
    let matrix_size = num_constraints_padded * num_vars_padded;
    
    // Calculate vars needed: 2^vars >= matrix_size
    let required_vars = (matrix_size as f64).log2().ceil() as usize;
    // Round up to even (Kopis-PC requirement)
    let setup_vars = if required_vars % 2 == 0 { required_vars } else { required_vars + 1 };
    setup_vars.max(4)
}

// =============================================================================
// Lakonia: Kopis-PC vs Dory-PC
// =============================================================================

fn bench_lakonia_pcs_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("lakonia_pcs");
    
    for log_size in [4, 6, 8].iter() {
        let n = 1usize << log_size;
        let (instance, witness) = create_mul_chain_r1cs(n);
        let setup_vars = calc_lakonia_vars(n);
        
        // Lakonia<KopisPCS>
        group.bench_with_input(
            BenchmarkId::new("kopis_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let lakonia = Lakonia::setup(setup_vars, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(lakonia.prove(&instance, &witness, &mut rng_clone))
                });
            },
        );
        
        // Lakonia<DoryPCS>
        group.bench_with_input(
            BenchmarkId::new("dory_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let lakonia = LakoniaDory::setup(setup_vars, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(lakonia.prove(&instance, &witness, &mut rng_clone))
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// Kopis: Kopis-PC vs Dory-PC
// =============================================================================

fn bench_kopis_pcs_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("kopis_pcs");
    
    // Smaller sizes to keep setup_vars manageable (avoids OOM)
    for log_size in [2, 3, 4].iter() {
        let n = 1usize << log_size;
        let (instance, witness) = create_mul_chain_r1cs(n);
        let setup_vars = calc_snark_vars(n);
        
        // Kopis<KopisPCS> - prove
        group.bench_with_input(
            BenchmarkId::new("kopis_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let kopis = Kopis::setup(setup_vars, &mut rng);
                let cc = kopis.preprocess(&instance, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(kopis.prove(&instance, &witness, &cc, &mut rng_clone))
                });
            },
        );
        
        // Kopis<DoryPCS> - prove
        group.bench_with_input(
            BenchmarkId::new("dory_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let kopis = KopisDory::setup(setup_vars, &mut rng);
                let cc = kopis.preprocess(&instance, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(kopis.prove(&instance, &witness, &cc, &mut rng_clone))
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// Xiphos: Dory-PC vs Kopis-PC
// =============================================================================

fn bench_xiphos_pcs_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("xiphos_pcs");
    
    for log_size in [2, 3, 4].iter() {
        let n = 1usize << log_size;
        let (instance, witness) = create_mul_chain_r1cs(n);
        let setup_vars = calc_snark_vars(n);
        
        // Xiphos<DoryPCS> - the "Quark"
        group.bench_with_input(
            BenchmarkId::new("dory_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let xiphos = Xiphos::setup(setup_vars, &mut rng);
                let cc = xiphos.preprocess(&instance, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(xiphos.prove(&instance, &witness, &cc, &mut rng_clone))
                });
            },
        );
        
        // Xiphos<KopisPCS>
        group.bench_with_input(
            BenchmarkId::new("kopis_pc_prove", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                let mut rng = test_rng();
                let xiphos = XiphosKopis::setup(setup_vars, &mut rng);
                let cc = xiphos.preprocess(&instance, &mut rng);
                b.iter(|| {
                    let mut rng_clone = test_rng();
                    black_box(xiphos.prove(&instance, &witness, &cc, &mut rng_clone))
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// Setup time comparison
// =============================================================================

fn bench_setup_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_setup");
    
    for setup_vars in [4, 6, 8, 10].iter() {
        // Kopis-PC setup (via Lakonia)
        group.bench_with_input(
            BenchmarkId::new("kopis_pc", format!("vars={}", setup_vars)),
            setup_vars,
            |b, &vars| {
                b.iter(|| {
                    let mut rng = test_rng();
                    black_box(Lakonia::setup(vars, &mut rng))
                });
            },
        );
        
        // Dory-PC setup (via LakoniaDory)
        group.bench_with_input(
            BenchmarkId::new("dory_pc", format!("vars={}", setup_vars)),
            setup_vars,
            |b, &vars| {
                b.iter(|| {
                    let mut rng = test_rng();
                    black_box(LakoniaDory::setup(vars, &mut rng))
                });
            },
        );
    }
    group.finish();
}

// =============================================================================
// Verification comparison (the key differentiator!)
// =============================================================================

fn bench_verification_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcs_verify");
    let mut rng = test_rng();
    
    for log_size in [2, 3, 4].iter() {
        let n = 1usize << log_size;
        let (instance, witness) = create_mul_chain_r1cs(n);
        let setup_vars = calc_snark_vars(n);
        
        // Kopis<KopisPCS> - O(√n) verification
        let kopis_k = Kopis::setup(setup_vars, &mut rng);
        let cc_k = kopis_k.preprocess(&instance, &mut rng);
        let proof_k = kopis_k.prove(&instance, &witness, &cc_k, &mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("kopis_pc_O(sqrt_n)", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| black_box(kopis_k.verify(&instance, &proof_k, &cc_k)));
            },
        );
        
        // Kopis<DoryPCS> - O(log n) verification
        let kopis_d = KopisDory::setup(setup_vars, &mut rng);
        let cc_d = kopis_d.preprocess(&instance, &mut rng);
        let proof_d = kopis_d.prove(&instance, &witness, &cc_d, &mut rng);
        
        group.bench_with_input(
            BenchmarkId::new("dory_pc_O(log_n)", format!("n=2^{}", log_size)),
            &n,
            |b, _| {
                b.iter(|| black_box(kopis_d.verify(&instance, &proof_d, &cc_d)));
            },
        );
    }
    group.finish();
}

// =============================================================================
// Full pipeline comparison
// =============================================================================

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.sample_size(100);
    
    let n = 1usize << 3; // 8 constraints (small to avoid OOM)
    let (instance, witness) = create_mul_chain_r1cs(n);
    let setup_vars = calc_snark_vars(n);
    
    // Xiphos<DoryPCS> - The "Quark" (O(log n) everything)
    group.bench_function("xiphos_dory_full", |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let xiphos = Xiphos::setup(setup_vars, &mut rng);
            let cc = xiphos.preprocess(&instance, &mut rng);
            let proof = xiphos.prove(&instance, &witness, &cc, &mut rng);
            let result = xiphos.verify(&instance, &proof, &cc);
            black_box((proof, result))
        });
    });
    
    // Xiphos<KopisPCS> - O(√n) verification
    group.bench_function("xiphos_kopis_full", |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let xiphos = XiphosKopis::setup(setup_vars, &mut rng);
            let cc = xiphos.preprocess(&instance, &mut rng);
            let proof = xiphos.prove(&instance, &witness, &cc, &mut rng);
            let result = xiphos.verify(&instance, &proof, &cc);
            black_box((proof, result))
        });
    });
    
    // Kopis<KopisPCS>
    group.bench_function("kopis_kopis_full", |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let kopis = Kopis::setup(setup_vars, &mut rng);
            let cc = kopis.preprocess(&instance, &mut rng);
            let proof = kopis.prove(&instance, &witness, &cc, &mut rng);
            let result = kopis.verify(&instance, &proof, &cc);
            black_box((proof, result))
        });
    });
    
    // Kopis<DoryPCS>
    group.bench_function("kopis_dory_full", |b| {
        b.iter(|| {
            let mut rng = test_rng();
            let kopis = KopisDory::setup(setup_vars, &mut rng);
            let cc = kopis.preprocess(&instance, &mut rng);
            let proof = kopis.prove(&instance, &witness, &cc, &mut rng);
            let result = kopis.verify(&instance, &proof, &cc);
            black_box((proof, result))
        });
    });
    
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = 
        bench_setup_comparison,
        bench_lakonia_pcs_comparison,
        bench_kopis_pcs_comparison,
        bench_xiphos_pcs_comparison,
        bench_verification_comparison,
        bench_full_pipeline
);
criterion_main!(benches);

