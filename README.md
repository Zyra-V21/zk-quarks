# Quarks-ZK

Rust implementation of Quarks zkSNARKs (Lakonia, Kopis, Xiphos) with pluggable polynomial commitment schemes.

[![Crates.io](https://img.shields.io/crates/v/quarks-zk.svg)](https://crates.io/crates/quarks-zk)
[![Documentation](https://docs.rs/quarks-zk/badge.svg)](https://docs.rs/quarks-zk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```toml
[dependencies]
quarks-zk = "0.1.2"
```

## Overview

This library implements the **Quarks** proof system from [Quarks: Quadruple-efficient transparent zkSNARKs](https://eprint.iacr.org/2020/1275) (Setty, Lee).

**Provided constructions:**
- Lakonia, Kopis, Xiphos SNARKs
- Kopis-PC and Dory-PC polynomial commitment schemes
- Generic `PolynomialCommitmentScheme` trait for backend interchangeability

## SNARKs

| SNARK | Prover | Verifier | Proof Size |
|-------|--------|----------|------------|
| Lakonia | O(n log n) | O(n) | O(log n) |
| Kopis | O(n log n) | O(√n) | O(√n) |
| Xiphos | O(n log n) | O(log n) | O(log n) |

## Polynomial Commitment Schemes

| PCS | Commitment | Proof Size | Verify |
|-----|------------|------------|--------|
| Kopis-PC | O(1) | O(√n) | O(√n) |
| Dory-PC | O(1) | O(log n) | O(log n) |

## Requirements

- Rust 1.70+
- Cargo

## Build

```bash
# Clone
git clone https://github.com/Zyra-V21/zk-quarks.git
cd zk-quarks

# Build
cargo build --release

# Build with all features
cargo build --release --all-features
```

## Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test --lib snark::lakonia
cargo test --lib kopis_pc
cargo test --lib dory_pc

# Run tests with output
cargo test -- --nocapture

# Run integration tests
cargo test --test dory_bls381_backend
```

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench pcs_comparison
cargo bench --bench snark_end_to_end
cargo bench --bench kopis_pc

# Available benchmarks:
# - pcs_comparison    : Compare Kopis-PC vs Dory-PC
# - snark_end_to_end  : Full SNARK pipeline
# - kopis_pc          : Kopis-PC operations
# - commitments       : Commitment schemes
# - polynomial        : Polynomial operations
# - sumcheck          : Sumcheck protocol
# - r1cs              : R1CS operations
```

### Benchmark Results

| Operation | Kopis-PC | Dory-PC |
|-----------|----------|---------|
| Setup (vars=10) | 511 µs | 124 ms |
| Prove (n=256) | 108 ms | 78 ms |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
quarks-zk = "0.1.3"
```

## Usage

```rust
use quarks_zk::{Lakonia, LakoniaDory, r1cs::R1CSInstance};
use ark_std::rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    let num_vars = 16;
    
    // Create R1CS instance
    let (instance, witness) = R1CSInstance::random(16, num_vars, &mut rng);
    
    // Lakonia with Kopis-PC (default)
    let params = Lakonia::setup(num_vars, &mut rng);
    let proof = Lakonia::prove(&params, &instance, &witness, &mut rng).unwrap();
    assert!(Lakonia::verify(&params, &instance, &proof).unwrap());
    
    // Lakonia with Dory-PC (O(log n) verification)
    let params = LakoniaDory::setup(num_vars, &mut rng);
    let proof = LakoniaDory::prove(&params, &instance, &witness, &mut rng).unwrap();
    assert!(LakoniaDory::verify(&params, &instance, &proof).unwrap());
}
```

## Generic PCS

```rust
use quarks_zk::traits::PolynomialCommitmentScheme;
use quarks_zk::{KopisPCS, DoryPCS};
use ark_bls12_381::Fr;

fn with_pcs<PCS: PolynomialCommitmentScheme<Fr>>(num_vars: usize) {
    let mut rng = ark_std::rand::thread_rng();
    let params = PCS::setup(num_vars, &mut rng);
    
    let evals: Vec<Fr> = (0..1 << num_vars)
        .map(|i| Fr::from(i as u64))
        .collect();
    
    let commitment = PCS::commit(&params, &evals);
    let point: Vec<Fr> = (0..num_vars).map(|_| Fr::from(1u64)).collect();
    let (proof, value) = PCS::prove_eval(&params, &evals, &point, &mut rng).unwrap();
    
    assert!(PCS::verify_eval(&params, &commitment, &point, value, &proof).unwrap());
}
```

## Project Structure

```
quarks-zk/
├── src/
│   ├── lib.rs                 # Public API
│   ├── traits/pcs.rs          # PolynomialCommitmentScheme trait
│   ├── snark/
│   │   ├── lakonia.rs         # Lakonia SNARK
│   │   ├── kopis.rs           # Kopis SNARK
│   │   └── xiphos.rs          # Xiphos SNARK
│   ├── kopis_pc/              # Kopis-PC (O(√n) verify)
│   ├── dory_pc/               # Dory-PC (O(log n) verify)
│   ├── commitments/           # BIPP, IPP, Pedersen
│   ├── r1cs/                  # R1CS constraint system
│   ├── sumcheck/              # Sumcheck protocol
│   └── polynomial/            # Multilinear polynomials
├── benches/                   # Criterion benchmarks
├── examples/                  # Usage examples
├── tests/                     # Integration tests
└── research/                  # Paper reference
```

## API Documentation

### Core Traits

#### PolynomialCommitmentScheme<F>

Generic trait for polynomial commitment schemes:

```rust
pub trait PolynomialCommitmentScheme<F: Field> {
    type Params;
    type Commitment;
    type EvaluationProof;
    
    fn setup<R: RngCore>(max_vars: usize, rng: &mut R) -> Self::Params;
    fn commit(params: &Self::Params, evals: &[F]) -> Self::Commitment;
    fn commit_hiding<R: RngCore>(params: &Self::Params, evals: &[F], rng: &mut R) -> Self::Commitment;
    fn prove_eval<R: RngCore>(params: &Self::Params, evals: &[F], point: &[F], rng: &mut R) -> (F, Self::EvaluationProof);
    fn verify_eval(params: &Self::Params, comm: &Self::Commitment, point: &[F], value: F, proof: &Self::EvaluationProof) -> bool;
}
```

### Dory-PC Rerandomization (v0.1.2+)

Support for zero-knowledge commitment reuse (Vega paper):

```rust
use quarks_zk::dory_pc::{DoryPCS, DoryPCSParams, DoryPCSCommitment};

// Setup includes h_gt generator for rerandomization
let params = DoryPCS::setup(num_vars, &mut rng);

// Original commitment
let commitment = DoryPCS::commit(&params, &evals);

// Rerandomize for unlinkable reuse
let r_delta = Fr::rand(&mut rng);
let rerandomized = commitment.rerandomize(&r_delta, &params.h_gt);

// Both commit to same value, but are unlinkable
assert_ne!(commitment.tier2, rerandomized.tier2);
```

### SNARK APIs

#### Lakonia SNARK

```rust
use quarks_zk::snark::{LakoniaSnark, KopisPCS};

let snark = LakoniaSnark::<KopisPCS>::setup(num_vars, &mut rng);
let proof = snark.prove(&instance, &witness, &mut rng);
assert!(snark.verify(&instance, &proof));
```

#### Kopis SNARK (with preprocessing)

```rust
use quarks_zk::snark::KopisSnark;

let snark = KopisSnark::<KopisPCS>::setup(num_vars, &mut rng);
let computation_commit = snark.preprocess(&instance, &mut rng);
let proof = snark.prove(&instance, &witness, &computation_commit, &mut rng);
assert!(snark.verify(&instance, &proof, &computation_commit));
```

#### Xiphos SNARK (Quadruple-efficient)

```rust
use quarks_zk::snark::{XiphosSnark, DoryPCS};

// With Dory-PC for O(log n) verification
let snark = XiphosSnark::<DoryPCS>::setup(num_vars, &mut rng);
let computation_commit = snark.preprocess(&instance, &mut rng);
let proof = snark.prove(&instance, &witness, &computation_commit, &mut rng);
assert!(snark.verify(&instance, &proof, &computation_commit));
```

## Examples

```bash
# Run proof generation example
cargo run --example generate_proof --release
```

## References

- [Quarks: Quadruple-efficient transparent zkSNARKs](https://eprint.iacr.org/2020/1275) - Setty, Lee
- [Dory: Efficient, Transparent arguments for Generalised Inner Products](https://eprint.iacr.org/2020/1274) - Lee
- [Spartan: Efficient and general-purpose zkSNARKs](https://eprint.iacr.org/2019/550) - Setty

See [research/PAPER.md](research/PAPER.md) for the complete paper reference.

## Disclaimer

**This is research software.** It has not been audited and should not be used in production environments. The implementation is provided for educational and research purposes only.

- No security audit has been performed
- The code may contain bugs or vulnerabilities
- APIs may change without notice
- Use at your own risk

If you require production-ready cryptographic software, consider using audited implementations.

## License

MIT - See [LICENSE](LICENSE)
