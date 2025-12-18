# Quarks-ZK

Rust implementation of **Quarks zkSNARKs** (Lakonia, Kopis, Xiphos) with pluggable polynomial commitment schemes.

[![Crates.io](https://img.shields.io/crates/v/quarks-zk.svg)](https://crates.io/crates/quarks-zk)
[![Documentation](https://docs.rs/quarks-zk/badge.svg)](https://docs.rs/quarks-zk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```toml
[dependencies]
quarks-zk = "0.1.5"
```

## What's New in 0.1.5

- **arkworks 0.5** with **GLV endomorphism** enabled by default (~1.5x faster scalar multiplication)
- Native CPU optimizations (AVX2, FMA, BMI2) via `target-cpu=native`
- BLS12-381 curve with optimized field arithmetic

## Overview

This library implements the **Quarks** proof system from [Quarks: Quadruple-efficient transparent zkSNARKs](https://eprint.iacr.org/2020/1275) (Setty, Lee 2020).

**Key features:**
- **Transparent setup** - no trusted setup required
- **Pluggable PCS** - swap between Kopis-PC and Dory-PC
- **BLS12-381** - 128-bit security level

## SNARKs

| SNARK | Prover | Verifier | Proof Size | Best For |
|-------|--------|----------|------------|----------|
| **Lakonia** | O(n log n) | O(n) | O(log n) | Short proofs |
| **Kopis** | O(n log n) | O(√n) | O(√n) | Balanced |
| **Xiphos** | O(n log n) | O(log n) | O(log n) | Fast verification |

## Polynomial Commitment Schemes

| PCS | Commitment | Proof Size | Verify | Setup |
|-----|------------|------------|--------|-------|
| **Kopis-PC** | O(1) | O(√n) | O(√n) | Fast |
| **Dory-PC** | O(1) | O(log n) | O(log n) | Slower |

## Quick Start

```rust
use quarks_zk::snark::lakonia::LakoniaSnark;
use quarks_zk::kopis_pc::KopisPCS;
use quarks_zk::r1cs::{R1CSInstance, Witness};
use ark_bls12_381::Fr;
use ark_std::rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    
    // Create R1CS instance (example: prove x * y = z)
    let num_constraints = 100;
    let num_vars = 104;
    let num_inputs = 3;
    let (instance, witness) = R1CSInstance::random(num_constraints, num_vars, num_inputs, &mut rng);
    
    // Setup Lakonia with Kopis-PC
    let snark = LakoniaSnark::<KopisPCS>::setup(num_vars.next_power_of_two().trailing_zeros() as usize, &mut rng);
    
    // Prove
    let proof = snark.prove(&instance, &witness, &mut rng);
    
    // Verify
    assert!(snark.verify(&instance, &proof));
    println!("Proof verified!");
}
```

## Type Aliases

For convenience, common configurations are pre-defined:

```rust
use quarks_zk::{
    Lakonia,      // LakoniaSnark<KopisPCS>
    LakoniaDory,  // LakoniaSnark<DoryPCS>
    Kopis,        // KopisSnark<KopisPCS>
    KopisDory,    // KopisSnark<DoryPCS>
    Xiphos,       // XiphosSnark<DoryPCS>
    XiphosKopis,  // XiphosSnark<KopisPCS>
};
```

## Choosing a Configuration

| Use Case | Recommended | Why |
|----------|-------------|-----|
| **Short proofs** | `Lakonia` | O(log n) proof size |
| **Fast verify** | `Xiphos` | O(log n) verifier |
| **Balanced** | `Kopis` | Good all-around |
| **On-chain** | `LakoniaDory` | Smallest proofs |

## Performance

Benchmarked on Intel i7-10750H @ 2.60GHz with AVX2:

| Circuit Size | Lakonia Prove | Lakonia Verify | Proof Size |
|--------------|---------------|----------------|------------|
| 2^10 (1K) | ~200ms | ~30ms | ~1.5KB |
| 2^12 (4K) | ~400ms | ~40ms | ~1.5KB |
| 2^14 (16K) | ~800ms | ~60ms | ~1.5KB |

*Times include setup. Enable `target-cpu=native` for best performance.*

## Build

```bash
git clone https://github.com/Zyra-V21/zk-quarks.git
cd zk-quarks

# Build with optimizations
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Recommended: Enable CPU optimizations

Create `.cargo/config.toml`:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

## Project Structure

```
quarks-zk/
├── src/
│   ├── lib.rs              # Public API & type aliases
│   ├── snark/
│   │   ├── lakonia.rs      # Lakonia SNARK
│   │   ├── kopis.rs        # Kopis SNARK  
│   │   ├── xiphos.rs       # Xiphos SNARK
│   │   └── common.rs       # Shared types (Proof, Witness)
│   ├── kopis_pc/           # Kopis-PC (O(√n) verify)
│   ├── dory_pc/            # Dory-PC (O(log n) verify)
│   ├── r1cs/               # R1CS constraint system
│   ├── sumcheck/           # Sumcheck protocol
│   ├── polynomial/         # Multilinear polynomials
│   └── commitments/        # BIPP, IPP, Pedersen
├── benches/                # Criterion benchmarks
└── tests/                  # Integration tests
```

## API Reference

### LakoniaSnark

```rust
impl<PCS: PolynomialCommitmentScheme<Fr>> LakoniaSnark<PCS> {
    /// Setup with max number of variables (log2 of constraint count)
    pub fn setup<R: RngCore>(max_num_vars: usize, rng: &mut R) -> Self;
    
    /// Generate a proof
    pub fn prove<R: RngCore>(
        &self,
        instance: &R1CSInstance<Fr>,
        witness: &Witness,
        rng: &mut R,
    ) -> Proof;
    
    /// Verify a proof
    pub fn verify(&self, instance: &R1CSInstance<Fr>, proof: &Proof) -> bool;
}
```

### Witness

```rust
use quarks_zk::r1cs::Witness;

// From public inputs + private assignments
let witness = Witness {
    public_inputs: vec![x, y, z],
    assignments: vec![a, b, c, ...],
};

// Build z vector: [1, public_inputs..., assignments...]
let z = witness.build_z();
```

### R1CSInstance

```rust
use quarks_zk::r1cs::R1CSInstance;

// Create from sparse matrices A, B, C where Az ∘ Bz = Cz
let instance = R1CSInstance::new(a, b, c, num_constraints, num_vars, num_inputs);

// Or generate random for testing
let (instance, witness) = R1CSInstance::random(100, 104, 3, &mut rng);
```

## References

- [Quarks: Quadruple-efficient transparent zkSNARKs](https://eprint.iacr.org/2020/1275) - Setty, Lee 2020
- [Dory: Efficient, Transparent arguments for Generalised Inner Products](https://eprint.iacr.org/2020/1274) - Lee 2020
- [Spartan: Efficient and general-purpose zkSNARKs](https://eprint.iacr.org/2019/550) - Setty 2019

## Disclaimer

**This is research software.** It has not been audited and should not be used in production environments.

- No security audit has been performed
- The code may contain bugs or vulnerabilities  
- APIs may change without notice

## License

MIT - See [LICENSE](LICENSE)
