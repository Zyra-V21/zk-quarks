# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2024-12-11

### Added
- **Dory-PC Rerandomization**: Support for commitment rerandomization (Vega paper §2.1)
  - Enables zero-knowledge reuse of precomputed commitments
  - Prevents linkability attacks across presentations
  - `DoryPCSCommitment::rerandomize()` method
  - `h_gt` generator in `DoryPCSParams` for rerandomization
- **Rigorous Tests**: 4 new tests validating rerandomization unlinkability and correctness

### References
- Vega paper (eprint 2025/2094) for rerandomization approach

## [0.1.1] - 2024-12-11

### Added
- **Full PCS Verification**: Complete cryptographic verification in SNARK verifiers
  - Added `pcs_eval_proof`, `eval_point`, `claimed_eval` to `Proof` struct
  - Lakonia, Kopis, Xiphos now call `PCS::prove_eval` and `PCS::verify_eval`
  - Verifiers perform real cryptographic checks, not just structural validation

### Changed
- Fixed KopisPCS `commit_hiding` to be deterministic for consistency with `prove_eval`

### Fixed
- ZK sumcheck now uses proper Fiat-Shamir (challenges derived from transcript, not random)

## [0.1.0] - 2024-12-10

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

