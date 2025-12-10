//! Blake2b-based Fiat-Shamir transcript for Dory proofs with BLS12-381

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use super::BLS12381;
use super::bls_field::Bls381Fr;
use crate::dory_pc::primitives::arithmetic::{Group, PairingCurve};
use crate::dory_pc::primitives::serialization::Compress;
use crate::dory_pc::primitives::transcript::Transcript;
use crate::dory_pc::primitives::DorySerialize;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
use digest::{Digest, Output};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Blake2bTranscript {
    hasher: Blake2b512,
    _phantom: PhantomData<BLS12381>,
}

impl Blake2bTranscript {
    pub fn new(domain_label: &[u8]) -> Self {
        let mut hasher = Blake2b512::default();
        hasher.update(domain_label);
        Self {
            hasher,
            _phantom: PhantomData,
        }
    }

    fn append_bytes_impl(&mut self, label: &[u8], bytes: &[u8]) {
        self.hasher.update(label);
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    fn append_field_impl<F: PrimeField>(&mut self, label: &[u8], x: &F) {
        self.append_bytes_impl(label, &x.into_bigint().to_bytes_le());
    }

    #[allow(dead_code)]
    fn append_group_impl<G: CanonicalSerialize>(&mut self, label: &[u8], g: &G) {
        let mut bytes = Vec::new();
        g.serialize_compressed(&mut bytes)
            .expect("Serialization should not fail");
        self.append_bytes_impl(label, &bytes);
    }

    fn challenge_scalar_impl<F: PrimeField>(&mut self, label: &[u8]) -> F {
        self.hasher.update(label);

        let h = self.hasher.clone();
        let digest: Output<Blake2b512> = h.finalize();

        let repr = digest.to_vec();
        let fe = F::from_le_bytes_mod_order(&repr);

        if fe.is_zero() {
            panic!("Challenge scalar cannot be zero")
        }

        self.hasher.update(&repr);

        fe
    }

    fn reset_impl(&mut self, domain_label: &[u8]) {
        let mut hasher = Blake2b512::default();
        hasher.update(domain_label);
        self.hasher = hasher;
        self._phantom = PhantomData;
    }
}

impl Transcript for Blake2bTranscript {
    type Curve = BLS12381;

    fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_bytes_impl(label, bytes);
    }

    fn append_field(
        &mut self,
        label: &[u8],
        x: &<<BLS12381 as PairingCurve>::G1 as Group>::Scalar,
    ) {
        self.append_field_impl(label, &x.0);
    }

    fn append_group<G: Group + DorySerialize>(&mut self, label: &[u8], g: &G) {
        let mut bytes: Vec<u8> = Vec::new();
        g.serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("DorySerialize should not fail");
        self.append_bytes_impl(label, &bytes);
    }

    fn append_serde<S: DorySerialize>(&mut self, label: &[u8], s: &S) {
        let mut bytes: Vec<u8> = Vec::new();
        s.serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("DorySerialize should not fail");
        self.append_bytes_impl(label, &bytes);
    }

    fn challenge_scalar(&mut self, label: &[u8]) -> Bls381Fr {
        Bls381Fr(self.challenge_scalar_impl(label))
    }

    fn reset(&mut self, domain_label: &[u8]) {
        self.reset_impl(domain_label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_consistency() {
        let mut t1 = Blake2bTranscript::new(b"demo");
        let mut t2 = Blake2bTranscript::new(b"demo");

        // Same sequence of messages => same challenge
        t1.append_bytes(b"m", b"hello");
        t2.append_bytes(b"m", b"hello");

        let c1 = t1.challenge_scalar(b"x");
        let c2 = t2.challenge_scalar(b"x");

        assert_eq!(c1, c2);
    }

    #[test]
    fn transcript_different_messages() {
        let mut t1 = Blake2bTranscript::new(b"demo");
        let mut t2 = Blake2bTranscript::new(b"demo");

        t1.append_bytes(b"m", b"hello");
        t2.append_bytes(b"m", b"world");

        let c1 = t1.challenge_scalar(b"x");
        let c2 = t2.challenge_scalar(b"x");

        assert_ne!(c1, c2);
    }
}

