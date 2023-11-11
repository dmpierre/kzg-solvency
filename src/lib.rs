mod kzg;
mod lagrange;
mod prover;

#[cfg(test)]
mod tests {
    use crate::prover::User;

    use super::*;
    use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
    use ark_poly::polynomial::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::EvaluationDomain;
    use ark_poly::Evaluations;
    use ark_poly::GeneralEvaluationDomain;
    use ark_poly::Polynomial;
    use ark_std::rand::Rng;
    use ark_std::UniformRand;
    use ark_std::{test_rng, Zero};
    use kzg::KZG;
    use lagrange::lagrange_interpolate;
    use prover::generate_witness;

    #[test]
    fn test_kzg_bn254() {
        let mut rng = test_rng();
        let degree = 10;
        let polynomial: DensePolynomial<F> = DenseUVPolynomial::rand(degree, &mut rng);
        let tau = F::rand(&mut rng);
        let random_z = F::rand(&mut rng);
        let y = polynomial.evaluate(&random_z);
        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);

        let mut kzg_bn254 = KZG::<Bn254>::new(g1, g2, degree);

        let _ = kzg_bn254.setup(tau); // setup modifies in place the struct crs
        let commitment = kzg_bn254.commit(&polynomial);
        let opening = kzg_bn254.open(&polynomial, random_z, y);
        let verify = kzg_bn254.verify(y, random_z, commitment, opening);
        assert!(verify);
    }

    #[test]
    fn multi_opening() {
        let mut rng = test_rng();
        let degree = 10;
        let polynomial: DensePolynomial<F> = DenseUVPolynomial::rand(degree, &mut rng);

        let omegas = GeneralEvaluationDomain::<F>::new(3).unwrap();
        let evals = vec![F::from(12), F::from(123), F::from(1234)];
        let lagrange: DensePolynomial<F> =
            Evaluations::<F>::from_vec_and_domain(evals, omegas).interpolate();

        dbg!(lagrange.coeffs());

        fn test_lagrange() {
            let balances = vec![
                F::from(20),
                F::from(50),
                F::from(10),
                F::from(164),
                F::from(870),
                F::from(6),
                F::from(270),
                F::from(90),
            ];

            let poly = lagrange_interpolate(&balances);

            let omegas = GeneralEvaluationDomain::<F>::new(1 << 3).unwrap();

            for (i, omega) in omegas.elements().enumerate() {
                assert_eq!(poly.evaluate(&omega), balances[i]);
            }
        }

        #[test]
        fn test_witness_gen() {
            let mut rng = test_rng();

            let balances = vec![20, 50, 10, 164, 870, 6, 270, 90];

            let users = balances
                .iter()
                .take(8)
                .map(|&balance| User {
                    username: rng.gen_range(0..1000),
                    balance,
                    salt: rng.gen_range(0..1000),
                })
                .collect::<Vec<User>>();

            let (p_witness, i_witness) = generate_witness(users.clone()).unwrap();

            // check that p witnesss and i_witness are built correctly
            for (i, user) in users.iter().enumerate() {
                assert_eq!(p_witness[2 * i], F::from(user.username + user.salt));
                assert_eq!(p_witness[2 * i + 1], F::from(user.balance));
                assert_eq!(i_witness[14 + 16 * i], F::from(user.balance));
                assert_eq!(i_witness[16 * i], F::zero());

                // The last running total should be equal to 0
                if i == users.len() - 1 {
                    assert_eq!(i_witness[15 + 16 * i], F::zero());
                }
            }
        }
    }
}
