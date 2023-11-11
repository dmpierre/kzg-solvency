pub mod kzg;
pub mod lagrange;
pub mod prover;
pub mod utils;
pub mod misc;

#[cfg(test)]
mod tests {
    use crate::prover::User;
    use crate::utils::build_zero_polynomial;
    use crate::utils::compute_evaluations_for_specific_omegas;
    use crate::utils::generate_random_scalar_field_elements;
    use crate::utils::get_omega_domain;

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

        // Build our polynomial P(X). It consists of users usernames and balances
        let n_users = 8;
        let n_leaves = n_users * 2; // user consists of (h(username), leaf)

        // p_omegas consists in the domain of P(X). we also store them in domain_elements
        let (p_omegas, domain_elements) = get_omega_domain::<Bn254>(n_leaves);

        // P(omega^i) = random * i
        let p_evaluations = generate_random_scalar_field_elements::<Bn254>(&mut rng, n_leaves);
        let P: DensePolynomial<F> =
            Evaluations::<F>::from_vec_and_domain(p_evaluations.clone(), p_omegas).interpolate();

        let mut kzg_bn254 = KZG::<Bn254>::new(G1::rand(&mut rng), G2::rand(&mut rng), n_leaves - 1);
        let _ = kzg_bn254.setup(F::rand(&mut rng));
        let commitment = kzg_bn254.commit(&P);

        // Build polynomial L(X), that consists into the "opening" of (username, balance)
        // we want the L(X) interpolated polynomial to be defined over the same domain of P
        // When evaluated at omega^2 and omega^3, it will be equal to P(omega^2) and P(omega^3)
        let l_omegas = p_omegas.clone();
        let l_evaluations =
            compute_evaluations_for_specific_omegas::<Bn254>(vec![2, 3], &domain_elements, &P);
        let L: DensePolynomial<F> =
            Evaluations::<F>::from_vec_and_domain(l_evaluations.clone(), l_omegas).interpolate();

        // Build denominator polynomial Z(X) in [(P(x) - Q(X)) / Z(X)]
        let Z = build_zero_polynomial::<Bn254>(&vec![domain_elements[2], domain_elements[3]]);

        // Perform multi opening, z is a vector of points at which we want to prove an opening for specific values
        let pi = kzg_bn254.multi_open(&P, &L, vec![domain_elements[2], domain_elements[3]]);
        let verify = kzg_bn254.verify_multi_open(commitment, pi, &Z, &L);
        assert!(verify);

        let verify_wrong = kzg_bn254.verify_multi_open(commitment, pi * F::from(2134), &Z, &L);
        assert!(!verify_wrong);
    }

    #[test]
    fn compute_Q() {
        let mut rng = test_rng();

        // Build our polynomial P(X). It consists of users usernames and balances
        let n_users = 8;
        let n_leaves = n_users * 2; // user consists of (h(username), leaf)
        let p_omegas = GeneralEvaluationDomain::<F>::new(n_leaves).unwrap();

        // Our omegas (domain of P(X)) in a vector that we will access later on
        let mut domain_elements: Vec<F> = vec![];
        for element in p_omegas.elements() {
            domain_elements.push(element);
        }

        let mut p_evaluations = vec![];
        for i in 0..n_leaves {
            // P(omega^i) = random * i
            let eval = F::rand(&mut rng) * F::from(i as u32);
            p_evaluations.push(eval);
        }
        let P: DensePolynomial<F> =
            Evaluations::<F>::from_vec_and_domain(p_evaluations.clone(), p_omegas).interpolate();

        // Build polynomial L(X), that consists into the "opening" of (username, balance)
        // we want the L(X) interpolated polynomial to be defined over the same domain of P
        // When evaluated at omega^2 and omega^3, it needs to be equal to P(omega^2) and P(omega^3)
        let l_omegas = p_omegas.clone();
        let mut l_evaluations = vec![];
        for (i, element) in domain_elements.iter().enumerate() {
            if i == 2 || i == 3 {
                // at omega^2 and omega^3, we want to have P(omega^2) and P(omega^3)
                let eval = P.evaluate(&element);
                l_evaluations.push(eval);
            } else {
                l_evaluations.push(F::zero());
            }
        }
        let L: DensePolynomial<F> =
            Evaluations::<F>::from_vec_and_domain(l_evaluations.clone(), l_omegas).interpolate();

        // Build denominator polynomial Z(X) in [(P(x) - Q(X)) / Z(X)]
        // here roots of Z(X) will be omega^{2} and omega^{3}
        let l_root_username: DensePolynomial<F> = DenseUVPolynomial::from_coefficients_vec(vec![
            domain_elements[2] * F::from(-1),
            F::from(1),
        ]);
        let l_root_balance: DensePolynomial<F> = DenseUVPolynomial::from_coefficients_vec(vec![
            domain_elements[3] * F::from(-1),
            F::from(1),
        ]);
        let Z = &l_root_username * &l_root_balance;

        // Build final polynomial Q(X)
        let Q = &(&P - &L) / (&Z);

        // L(X) and Z(X) do not have the same coeffs
        assert_ne!(L.coeffs(), Z.coeffs());

        // L(X) and Z(X) evaluate to the same values at at omega^2 and omega^3
        assert_eq!(
            L.evaluate(&domain_elements[2]),
            P.evaluate(&domain_elements[2])
        );
        assert_eq!(
            L.evaluate(&domain_elements[3]),
            P.evaluate(&domain_elements[3])
        );

        // Z(X) has roots at omega^2 and omega^3
        assert_eq!(Z.evaluate(&domain_elements[2]), F::zero());
        assert_eq!(Z.evaluate(&domain_elements[3]), F::zero());
    }

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

        let (p_witness, i_witness) = generate_witness::<Bn254>(users.clone()).unwrap();

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
