use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
use ark_poly::{polynomial::Polynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{rand::Rng, test_rng, UniformRand};
use kzg_solvency::{kzg::KZG, lagrange::lagrange_interpolate, prover::User};

fn main() {
    // 1. Generate input users data
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

    // 2. Generate witness tables
    let (p_witness, i_witness) = kzg_solvency::prover::generate_witness(users).unwrap();

    // 3. Interpolate witness tables into polynomials
    let p_poly = lagrange_interpolate(&p_witness);
    let i_poly = lagrange_interpolate(&i_witness);

    // 4. Commit to polynomial p
    let tau = F::rand(&mut rng);

    // TO DO: Why is it random?
    let g1 = G1::rand(&mut rng);
    let g2 = G2::rand(&mut rng);

    let p_degree = p_poly.degree();
    let mut kzg_bn254 = KZG::<Bn254>::new(g1, g2, p_degree);

    kzg_bn254.setup(tau); // setup modifies in place the struct crs
    let p_commitment = kzg_bn254.commit(&p_poly);

    // 5. Generate opening proof for polynomial p at index 1 (user 0 balance)
    let index = 1;

    let k = 4; // 2^k = 16
    let omegas = GeneralEvaluationDomain::<F>::new(1 << k).unwrap();

    let expected_opening_value = F::from(balances[0]); // user 0 balance

    let opening_proof_p_user_0 =
        kzg_bn254.open(&p_poly, omegas.element(index), expected_opening_value);

    // 6. User 0 verifies opening proof for their balance
    let verify = kzg_bn254.verify(
        expected_opening_value,
        omegas.element(index),
        p_commitment,
        opening_proof_p_user_0,
    );

    assert!(verify);
}
