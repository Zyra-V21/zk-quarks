//! Equality polynomial ẽq(x, e) = Π_i (e_i·x_i + (1-e_i)·(1-x_i))

use ark_ff::Field;

/// Evaluate equality polynomial at point `x` for Boolean vector `e`
pub fn eq_polynomial<F: Field>(x: &[F], e: &[bool]) -> F {
    assert_eq!(x.len(), e.len(), "dimension mismatch");
    let mut acc = F::one();
    for (xi, &ei) in x.iter().zip(e.iter()) {
        let term = if ei {
            *xi
        } else {
            F::one() - xi
        };
        acc *= term;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Bls12381Fr as Fr;
    use ark_std::test_rng;
    use rand::Rng;
    use ark_ff::{One, Zero};

    #[test]
    fn eq_hits_one_on_vertex() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let len = 1 + (rng.gen::<u8>() % 5) as usize;
            let e: Vec<bool> = (0..len).map(|_| rng.gen::<bool>()).collect();
            let x: Vec<Fr> = e.iter().map(|&b| if b { Fr::one() } else { Fr::zero() }).collect();
            let val = eq_polynomial(&x, &e);
            assert_eq!(val, Fr::one());
        }
    }

    #[test]
    fn eq_zero_off_vertex() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let len = 2 + (rng.gen::<u8>() % 4) as usize;
            let e: Vec<bool> = (0..len).map(|_| rng.gen::<bool>()).collect();
            // choose a differing position
            let mut x: Vec<Fr> = e.iter().map(|&b| if b { Fr::one() } else { Fr::zero() }).collect();
            let idx = (rng.gen::<usize>() % len) as usize;
            x[idx] = if e[idx] { Fr::zero() } else { Fr::one() }; // flip to differ
            let val = eq_polynomial(&x, &e);
            assert_eq!(val, Fr::zero());
        }
    }
}

