//! BLS12-381 pairing implementation

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use super::bls_group::{Bls381G1, Bls381G2, Bls381GT};
use crate::dory_pc::primitives::arithmetic::{Group, PairingCurve};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::One;

#[derive(Default, Clone, Debug)]
pub struct BLS12381;

mod pairing_helpers {
    use super::*;
    use super::{Bls381G1, Bls381G2, Bls381GT};

    /// Sequential multi-pairing (kept for future non-parallel builds)
    #[allow(dead_code)]
    #[tracing::instrument(skip_all, name = "multi_pair_sequential", fields(len = ps.len()))]
    pub(super) fn multi_pair_sequential(ps: &[Bls381G1], qs: &[Bls381G2]) -> Bls381GT {
        use ark_bls12_381::{G1Affine, G2Affine};

        let ps_prep: Vec<<Bls12_381 as Pairing>::G1Prepared> = ps
            .iter()
            .map(|p| {
                let affine: G1Affine = p.0.into();
                affine.into()
            })
            .collect();

        let qs_prep: Vec<<Bls12_381 as Pairing>::G2Prepared> = qs
            .iter()
            .map(|q| {
                let affine: G2Affine = q.0.into();
                affine.into()
            })
            .collect();

        multi_pair_with_prepared(ps_prep, &qs_prep)
    }

    #[allow(dead_code)]
    fn multi_pair_with_prepared(
        ps_prep: Vec<<Bls12_381 as Pairing>::G1Prepared>,
        qs_prep: &[<Bls12_381 as Pairing>::G2Prepared],
    ) -> Bls381GT {
        let miller_output = Bls12_381::multi_miller_loop(ps_prep, qs_prep.to_vec());
        let result = Bls12_381::final_exponentiation(miller_output)
            .expect("Final exponentiation should not fail");
        Bls381GT(result.0)
    }

    /// Parallel multi-pairing with chunked Miller loops
    #[tracing::instrument(skip_all, name = "multi_pair_parallel", fields(len = ps.len()))]
    pub(super) fn multi_pair_parallel(ps: &[Bls381G1], qs: &[Bls381G2]) -> Bls381GT {
        use ark_bls12_381::{G1Affine, G2Affine};
        use rayon::prelude::*;

        const CHUNK_SIZE: usize = 64;

        let combined = ps
            .par_chunks(CHUNK_SIZE)
            .zip(qs.par_chunks(CHUNK_SIZE))
            .map(|(ps_chunk, qs_chunk)| {
                let ps_prep: Vec<<Bls12_381 as Pairing>::G1Prepared> = ps_chunk
                    .iter()
                    .map(|p| {
                        let affine: G1Affine = p.0.into();
                        affine.into()
                    })
                    .collect();

                let qs_prep: Vec<<Bls12_381 as Pairing>::G2Prepared> = qs_chunk
                    .iter()
                    .map(|q| {
                        let affine: G2Affine = q.0.into();
                        affine.into()
                    })
                    .collect();

                Bls12_381::multi_miller_loop(ps_prep, qs_prep)
            })
            .reduce(
                || ark_ec::pairing::MillerLoopOutput(<<Bls12_381 as Pairing>::TargetField>::one()),
                |a, b| ark_ec::pairing::MillerLoopOutput(a.0 * b.0),
            );

        let result =
            Bls12_381::final_exponentiation(combined).expect("Final exponentiation should not fail");
        Bls381GT(result.0)
    }

    /// Optimized multi-pairing dispatch (always uses parallel version with rayon)
    pub(super) fn multi_pair_optimized(ps: &[Bls381G1], qs: &[Bls381G2]) -> Bls381GT {
        multi_pair_parallel(ps, qs)
    }
}

impl PairingCurve for BLS12381 {
    type G1 = Bls381G1;
    type G2 = Bls381G2;
    type GT = Bls381GT;

    fn pair(p: &Self::G1, q: &Self::G2) -> Self::GT {
        Bls381GT(Bls12_381::pairing(p.0, q.0).0)
    }

    #[tracing::instrument(skip_all, name = "BLS12381::multi_pair", fields(len = ps.len()))]
    fn multi_pair(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        assert_eq!(
            ps.len(),
            qs.len(),
            "multi_pair requires equal length vectors"
        );

        if ps.is_empty() {
            return Self::GT::identity();
        }

        pairing_helpers::multi_pair_optimized(ps, qs)
    }

    #[tracing::instrument(skip_all, name = "BLS12381::multi_pair_g2_setup", fields(len = ps.len()))]
    fn multi_pair_g2_setup(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        // BLS12-381 backend doesn't use setup caching yet
        Self::multi_pair(ps, qs)
    }

    #[tracing::instrument(skip_all, name = "BLS12381::multi_pair_g1_setup", fields(len = ps.len()))]
    fn multi_pair_g1_setup(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        // BLS12-381 backend doesn't use setup caching yet
        Self::multi_pair(ps, qs)
    }
}

