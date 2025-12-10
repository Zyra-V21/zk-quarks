//! Group implementations for BLS12-381 curve (G1, G2, GT)

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use super::bls_field::Bls381Fr;
use crate::dory_pc::primitives::arithmetic::{DoryRoutines, Group};
use ark_bls12_381::{Fq12, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field as ArkField, One, PrimeField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg, Sub};
use ark_std::rand::RngCore;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bls381G1(pub G1Projective);

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bls381G2(pub G2Projective);

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bls381GT(pub Fq12);

impl Group for Bls381G1 {
    type Scalar = Bls381Fr;

    fn identity() -> Self {
        Bls381G1(ArkZero::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        Bls381G1(self.0 + rhs.0)
    }

    fn neg(&self) -> Self {
        Bls381G1(-self.0)
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        Bls381G1(self.0 * k.0)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        Bls381G1(G1Projective::rand(rng))
    }
}

impl Add for Bls381G1 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Bls381G1(self.0 + rhs.0)
    }
}

impl Sub for Bls381G1 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Bls381G1(self.0 - rhs.0)
    }
}

impl Neg for Bls381G1 {
    type Output = Self;
    fn neg(self) -> Self {
        Bls381G1(-self.0)
    }
}

impl<'a> Add<&'a Bls381G1> for Bls381G1 {
    type Output = Bls381G1;
    fn add(self, rhs: &'a Bls381G1) -> Bls381G1 {
        Bls381G1(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Bls381G1> for Bls381G1 {
    type Output = Bls381G1;
    fn sub(self, rhs: &'a Bls381G1) -> Bls381G1 {
        Bls381G1(self.0 - rhs.0)
    }
}

impl Mul<Bls381G1> for Bls381Fr {
    type Output = Bls381G1;
    fn mul(self, rhs: Bls381G1) -> Bls381G1 {
        Bls381G1(rhs.0 * self.0)
    }
}

impl<'a> Mul<&'a Bls381G1> for Bls381Fr {
    type Output = Bls381G1;
    fn mul(self, rhs: &'a Bls381G1) -> Bls381G1 {
        Bls381G1(rhs.0 * self.0)
    }
}

impl Group for Bls381G2 {
    type Scalar = Bls381Fr;

    fn identity() -> Self {
        Bls381G2(ArkZero::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        Bls381G2(self.0 + rhs.0)
    }

    fn neg(&self) -> Self {
        Bls381G2(-self.0)
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        Bls381G2(self.0 * k.0)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        Bls381G2(G2Projective::rand(rng))
    }
}

impl Add for Bls381G2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Bls381G2(self.0 + rhs.0)
    }
}

impl Sub for Bls381G2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Bls381G2(self.0 - rhs.0)
    }
}

impl Neg for Bls381G2 {
    type Output = Self;
    fn neg(self) -> Self {
        Bls381G2(-self.0)
    }
}

impl<'a> Add<&'a Bls381G2> for Bls381G2 {
    type Output = Bls381G2;
    fn add(self, rhs: &'a Bls381G2) -> Bls381G2 {
        Bls381G2(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Bls381G2> for Bls381G2 {
    type Output = Bls381G2;
    fn sub(self, rhs: &'a Bls381G2) -> Bls381G2 {
        Bls381G2(self.0 - rhs.0)
    }
}

impl Mul<Bls381G2> for Bls381Fr {
    type Output = Bls381G2;
    fn mul(self, rhs: Bls381G2) -> Bls381G2 {
        Bls381G2(rhs.0 * self.0)
    }
}

impl<'a> Mul<&'a Bls381G2> for Bls381Fr {
    type Output = Bls381G2;
    fn mul(self, rhs: &'a Bls381G2) -> Bls381G2 {
        Bls381G2(rhs.0 * self.0)
    }
}

impl Group for Bls381GT {
    type Scalar = Bls381Fr;

    fn identity() -> Self {
        Bls381GT(Fq12::one())
    }

    fn add(&self, rhs: &Self) -> Self {
        // GT is multiplicative group, so add = multiply in Fq12
        Bls381GT(self.0 * rhs.0)
    }

    fn neg(&self) -> Self {
        Bls381GT(ArkField::inverse(&self.0).expect("GT inverse"))
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        Bls381GT(self.0.pow(k.0.into_bigint()))
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        Bls381GT(Fq12::rand(rng))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Bls381GT {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        // GT is a multiplicative group, so group addition is field multiplication
        Bls381GT(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for Bls381GT {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        // GT is a multiplicative group, so group subtraction is multiplication by inverse
        Bls381GT(self.0 * rhs.0.inverse().expect("GT inverse"))
    }
}

impl Neg for Bls381GT {
    type Output = Self;
    fn neg(self) -> Self {
        Bls381GT(self.0.inverse().expect("GT inverse"))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> Add<&'a Bls381GT> for Bls381GT {
    type Output = Bls381GT;
    fn add(self, rhs: &'a Bls381GT) -> Bls381GT {
        // GT is a multiplicative group, so group addition is field multiplication
        Bls381GT(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> Sub<&'a Bls381GT> for Bls381GT {
    type Output = Bls381GT;
    fn sub(self, rhs: &'a Bls381GT) -> Bls381GT {
        // GT is a multiplicative group, so group subtraction is multiplication by inverse
        Bls381GT(self.0 * rhs.0.inverse().expect("GT inverse"))
    }
}

impl Mul<Bls381GT> for Bls381Fr {
    type Output = Bls381GT;
    fn mul(self, rhs: Bls381GT) -> Bls381GT {
        Bls381GT(rhs.0.pow(self.0.into_bigint()))
    }
}

impl<'a> Mul<&'a Bls381GT> for Bls381Fr {
    type Output = Bls381GT;
    fn mul(self, rhs: &'a Bls381GT) -> Bls381GT {
        Bls381GT(rhs.0.pow(self.0.into_bigint()))
    }
}

pub struct G1Routines;

impl DoryRoutines<Bls381G1> for G1Routines {
    #[tracing::instrument(skip_all, name = "BLS381_G1::msm", fields(len = bases.len()))]
    fn msm(bases: &[Bls381G1], scalars: &[Bls381Fr]) -> Bls381G1 {
        assert_eq!(
            bases.len(),
            scalars.len(),
            "MSM requires equal length vectors"
        );

        if bases.is_empty() {
            return Bls381G1::identity();
        }

        let bases_affine: Vec<G1Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let scalars_fr: Vec<ark_bls12_381::Fr> = scalars.iter().map(|s| s.0).collect();

        Bls381G1(G1Projective::msm(&bases_affine, &scalars_fr).expect("MSM failed"))
    }

    fn fixed_base_vector_scalar_mul(base: &Bls381G1, scalars: &[Bls381Fr]) -> Vec<Bls381G1> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }

    fn fixed_scalar_mul_bases_then_add(bases: &[Bls381G1], vs: &mut [Bls381G1], scalar: &Bls381Fr) {
        assert_eq!(bases.len(), vs.len(), "Lengths must match");

        for (v, base) in vs.iter_mut().zip(bases.iter()) {
            *v = v.add(&base.scale(scalar));
        }
    }

    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls381G1], addends: &[Bls381G1], scalar: &Bls381Fr) {
        assert_eq!(vs.len(), addends.len(), "Lengths must match");

        for (v, addend) in vs.iter_mut().zip(addends.iter()) {
            *v = v.scale(scalar).add(addend);
        }
    }
}

pub struct G2Routines;

impl DoryRoutines<Bls381G2> for G2Routines {
    #[tracing::instrument(skip_all, name = "BLS381_G2::msm", fields(len = bases.len()))]
    fn msm(bases: &[Bls381G2], scalars: &[Bls381Fr]) -> Bls381G2 {
        assert_eq!(
            bases.len(),
            scalars.len(),
            "MSM requires equal length vectors"
        );

        if bases.is_empty() {
            return Bls381G2::identity();
        }

        let bases_affine: Vec<G2Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let scalars_fr: Vec<ark_bls12_381::Fr> = scalars.iter().map(|s| s.0).collect();

        Bls381G2(G2Projective::msm(&bases_affine, &scalars_fr).expect("MSM failed"))
    }

    fn fixed_base_vector_scalar_mul(base: &Bls381G2, scalars: &[Bls381Fr]) -> Vec<Bls381G2> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }

    fn fixed_scalar_mul_bases_then_add(bases: &[Bls381G2], vs: &mut [Bls381G2], scalar: &Bls381Fr) {
        assert_eq!(bases.len(), vs.len(), "Lengths must match");

        for (v, base) in vs.iter_mut().zip(bases.iter()) {
            *v = v.add(&base.scale(scalar));
        }
    }

    fn fixed_scalar_mul_vs_then_add(vs: &mut [Bls381G2], addends: &[Bls381G2], scalar: &Bls381Fr) {
        assert_eq!(vs.len(), addends.len(), "Lengths must match");

        for (v, addend) in vs.iter_mut().zip(addends.iter()) {
            *v = v.scale(scalar).add(addend);
        }
    }
}

