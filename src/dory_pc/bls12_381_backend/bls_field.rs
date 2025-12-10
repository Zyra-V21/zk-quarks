//! Field implementation for BLS12-381 Fr scalar field

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use crate::dory_pc::primitives::arithmetic::Field;
use ark_bls12_381::Fr;
use ark_ff::{Field as ArkField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg, Sub};
use ark_std::rand::RngCore;

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bls381Fr(pub Fr);

impl Field for Bls381Fr {
    fn zero() -> Self {
        Bls381Fr(Fr::from(0u64))
    }

    fn one() -> Self {
        Bls381Fr(Fr::from(1u64))
    }

    fn is_zero(&self) -> bool {
        ArkZero::is_zero(&self.0)
    }

    fn add(&self, rhs: &Self) -> Self {
        Bls381Fr(self.0 + rhs.0)
    }

    fn sub(&self, rhs: &Self) -> Self {
        Bls381Fr(self.0 - rhs.0)
    }

    fn mul(&self, rhs: &Self) -> Self {
        Bls381Fr(self.0 * rhs.0)
    }

    fn inv(self) -> Option<Self> {
        ArkField::inverse(&self.0).map(Bls381Fr)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        Bls381Fr(Fr::rand(rng))
    }

    fn from_u64(val: u64) -> Self {
        Bls381Fr(Fr::from(val))
    }

    fn from_i64(val: i64) -> Self {
        if val >= 0 {
            Bls381Fr(Fr::from(val as u64))
        } else {
            Bls381Fr(-Fr::from((-val) as u64))
        }
    }
}

impl Add for Bls381Fr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Bls381Fr(self.0 + rhs.0)
    }
}

impl Sub for Bls381Fr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Bls381Fr(self.0 - rhs.0)
    }
}

impl Mul for Bls381Fr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Bls381Fr(self.0 * rhs.0)
    }
}

impl Neg for Bls381Fr {
    type Output = Self;
    fn neg(self) -> Self {
        Bls381Fr(-self.0)
    }
}

impl<'a> Add<&'a Bls381Fr> for Bls381Fr {
    type Output = Bls381Fr;
    fn add(self, rhs: &'a Bls381Fr) -> Bls381Fr {
        Bls381Fr(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Bls381Fr> for Bls381Fr {
    type Output = Bls381Fr;
    fn sub(self, rhs: &'a Bls381Fr) -> Bls381Fr {
        Bls381Fr(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a Bls381Fr> for Bls381Fr {
    type Output = Bls381Fr;
    fn mul(self, rhs: &'a Bls381Fr) -> Bls381Fr {
        Bls381Fr(self.0 * rhs.0)
    }
}

