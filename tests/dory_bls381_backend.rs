//! Integration tests for Dory-PC BLS12-381 backend

use quarks::dory_pc::{
    BLS12381, Bls381Fr, Bls381G1, Bls381G2,
    Bls381Polynomial, Blake2bTranscript,
    G1Routines, G2Routines,
    setup, prove, verify,
};
use quarks::dory_pc::primitives::arithmetic::{Field, Group, PairingCurve};
use quarks::dory_pc::primitives::poly::Polynomial;
use ark_std::test_rng;

#[test]
fn test_field_operations() {
    let mut rng = test_rng();
    let a = Bls381Fr::random(&mut rng);
    let b = Bls381Fr::random(&mut rng);

    // Commutativity
    assert_eq!(a.add(&b), b.add(&a));
    
    // Associativity
    let c = Bls381Fr::random(&mut rng);
    assert_eq!(a.add(&b).add(&c), a.add(&b.add(&c)));
    
    // Identity
    assert_eq!(a.mul(&Bls381Fr::one()), a);
    assert_eq!(a.add(&Bls381Fr::zero()), a);
    
    // Inverse
    if let Some(a_inv) = a.inv() {
        assert_eq!(a.mul(&a_inv), Bls381Fr::one());
    }
}

#[test]
fn test_group_operations() {
    let mut rng = test_rng();
    let g1 = Bls381G1::random(&mut rng);
    let g2 = Bls381G1::random(&mut rng);
    let scalar = Bls381Fr::random(&mut rng);

    // Commutativity
    assert_eq!(g1.add(&g2), g2.add(&g1));
    
    // Identity
    assert_eq!(g1.add(&Bls381G1::identity()), g1);
    
    // Inverse
    assert_eq!(g1.add(&g1.neg()), Bls381G1::identity());
    
    // Scalar multiplication distributivity
    let g3 = g1.add(&g2);
    assert_eq!(g3.scale(&scalar), g1.scale(&scalar).add(&g2.scale(&scalar)));
}

#[test]
fn test_pairing_bilinearity() {
    let mut rng = test_rng();
    let g1 = Bls381G1::random(&mut rng);
    let g2 = Bls381G2::random(&mut rng);
    let a = Bls381Fr::random(&mut rng);
    let b = Bls381Fr::random(&mut rng);

    // e(aG1, bG2) = e(G1, G2)^(ab)
    let left = BLS12381::pair(&g1.scale(&a), &g2.scale(&b));
    let right = BLS12381::pair(&g1, &g2).scale(&a.mul(&b));
    assert_eq!(left, right);
}

#[test]
fn test_polynomial_evaluation() {
    // 2-variable polynomial: f(x,y) = 1 + 2x + 3y + 4xy
    // Coefficients in order: [f(0,0), f(1,0), f(0,1), f(1,1)]
    let coeffs = vec![
        Bls381Fr::from_u64(1),  // f(0,0) = 1
        Bls381Fr::from_u64(2),  // f(1,0) = 2
        Bls381Fr::from_u64(3),  // f(0,1) = 3
        Bls381Fr::from_u64(4),  // f(1,1) = 4
    ];
    
    let poly = Bls381Polynomial::new(coeffs);
    
    // Evaluate at (0,0)
    let point00 = vec![Bls381Fr::from_u64(0), Bls381Fr::from_u64(0)];
    assert_eq!(poly.evaluate(&point00), Bls381Fr::from_u64(1));
    
    // Evaluate at (1,0)
    let point10 = vec![Bls381Fr::from_u64(1), Bls381Fr::from_u64(0)];
    assert_eq!(poly.evaluate(&point10), Bls381Fr::from_u64(2));
    
    // Evaluate at (0,1)
    let point01 = vec![Bls381Fr::from_u64(0), Bls381Fr::from_u64(1)];
    assert_eq!(poly.evaluate(&point01), Bls381Fr::from_u64(3));
    
    // Evaluate at (1,1)
    let point11 = vec![Bls381Fr::from_u64(1), Bls381Fr::from_u64(1)];
    assert_eq!(poly.evaluate(&point11), Bls381Fr::from_u64(4));
}

#[test]
fn test_dory_e2e_small() {
    let mut rng = test_rng();
    
    // Setup for 4-variable polynomials (2^4 = 16 coefficients)
    let max_log_n = 4;
    let (prover_setup, verifier_setup) = setup::<BLS12381, _>(&mut rng, max_log_n);
    
    // Create a polynomial with 16 coefficients (nu=2, sigma=2)
    let coefficients: Vec<Bls381Fr> = (0..16)
        .map(|_| Bls381Fr::random(&mut rng))
        .collect();
    let polynomial = Bls381Polynomial::new(coefficients);
    
    // Evaluation point (4 variables)
    let point: Vec<Bls381Fr> = (0..4).map(|_| Bls381Fr::random(&mut rng)).collect();
    
    let nu = 2;     // log₂(rows) = 2 → 4 rows
    let sigma = 2;  // log₂(cols) = 2 → 4 columns
    
    // Commit
    let (tier_2, row_commitments) = polynomial
        .commit::<BLS12381, G1Routines>(nu, sigma, &prover_setup)
        .expect("Commit failed");
    
    // Generate proof
    let mut prover_transcript = Blake2bTranscript::new(b"dory-bls381-test");
    let proof = prove::<_, BLS12381, G1Routines, G2Routines, _, _>(
        &polynomial,
        &point,
        row_commitments,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    ).expect("Prove failed");
    
    // Verify
    let evaluation = polynomial.evaluate(&point);
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-bls381-test");
    verify::<_, BLS12381, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    ).expect("Verify failed");
}

#[test]
fn test_dory_e2e_larger() {
    let mut rng = test_rng();
    
    // Setup for 8-variable polynomials (2^8 = 256 coefficients)
    let max_log_n = 8;
    let (prover_setup, verifier_setup) = setup::<BLS12381, _>(&mut rng, max_log_n);
    
    // Create a polynomial with 256 coefficients (nu=4, sigma=4)
    let coefficients: Vec<Bls381Fr> = (0..256)
        .map(|i| Bls381Fr::from_u64(i as u64))
        .collect();
    let polynomial = Bls381Polynomial::new(coefficients);
    
    // Evaluation point (8 variables)
    let point: Vec<Bls381Fr> = (0..8).map(|_| Bls381Fr::random(&mut rng)).collect();
    
    let nu = 4;     // log₂(rows) = 4 → 16 rows
    let sigma = 4;  // log₂(cols) = 4 → 16 columns
    
    // Commit
    let (tier_2, row_commitments) = polynomial
        .commit::<BLS12381, G1Routines>(nu, sigma, &prover_setup)
        .expect("Commit failed");
    
    // Generate proof
    let mut prover_transcript = Blake2bTranscript::new(b"dory-bls381-large");
    let proof = prove::<_, BLS12381, G1Routines, G2Routines, _, _>(
        &polynomial,
        &point,
        row_commitments,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    ).expect("Prove failed");
    
    // Verify
    let evaluation = polynomial.evaluate(&point);
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-bls381-large");
    verify::<_, BLS12381, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    ).expect("Verify failed");
}

