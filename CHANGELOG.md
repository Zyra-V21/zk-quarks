# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-XX

### Added
- Initial release of quarks-zk
- **SNARKs**: Lakonia, Kopis, and Xiphos implementations
- **Polynomial Commitment Schemes**:
  - Kopis-PC with O(√n) verification
  - Dory-PC with O(log n) verification (via `dory-pcs` crate)
- **Generic PCS Trait**: `PolynomialCommitmentScheme<F>` for pluggable backends
- **Type Aliases**: Convenient aliases like `Lakonia`, `LakoniaDory`, etc.
- **R1CS Support**: Full R1CS constraint system support
- **Sumcheck Protocol**: Complete sumcheck implementation
- **Commitments**:
  - Pedersen commitments
  - Bilinear Inner Product Proofs (BIPP)
  - Hyrax-style Inner Product Proofs
- **BLS12-381**: Full support for BLS12-381 pairing-friendly curve
- **Serialization**: Complete proof serialization/deserialization
- **Benchmarks**: Criterion benchmarks for all components
- **Examples**: Proof generation examples

### References
- Based on ["Quarks: Quadruple-efficient transparent zkSNARKs"](https://eprint.iacr.org/2020/1275)

