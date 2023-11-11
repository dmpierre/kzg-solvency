use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
use ark_poly::{polynomial::Polynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{rand::Rng, test_rng, UniformRand};
use kzg_solvency::misc::{generate_random_balances, generate_users, greet};
use kzg_solvency::{kzg::KZG, lagrange::lagrange_interpolate, prover::User};

fn main() {
    greet();

    // 1. Setup
    let mut rng = test_rng();
    let n = 100;
    let balances = generate_random_balances(&mut rng, n);
    let users = generate_users(&mut rng, &balances);
    
    // Sampling a random tau and random generators g1 and g2
    let tau = F::rand(&mut rng);
    let g1 = G1::rand(&mut rng);
    let g2 = G2::rand(&mut rng);

    // 2. Generate witness tables
    // TO DO: witness should do hashing for username and salt.
    // Instantiating the witness tables over BN254. Should be working with other pairing groups.
    let (p_witness, i_witness) = kzg_solvency::prover::generate_witness::<Bn254>(users).unwrap();

    // 3. Interpolate witness tables into polynomials. i.e. computing P(X) and I(X)
    let p_poly = lagrange_interpolate(&p_witness);
    let i_poly = lagrange_interpolate(&i_witness);
    let poly_degree = p_poly.degree();
    let i_degree = i_poly.degree();

    assert_eq!(poly_degree, i_degree);

    // 4. Initiating KZG and committing to polynomials P(X) and I(X)
    let mut kzg_bn254 = KZG::<Bn254>::new(g1, g2, poly_degree);
    kzg_bn254.setup(tau); // setup modifies in place the struct crs
    let p_commitment = kzg_bn254.commit(&p_poly);
    let i_commitment = kzg_bn254.commit(&i_poly);

    // 4. Generate opening proof for polynomial p at index 1 (user 0 balance)
    let index = 1;

    let k = n * 16; // 100*16
    let omegas = GeneralEvaluationDomain::<F>::new(k).unwrap();

    let expected_opening_value = F::from(balances[0]); // user 0 balance

    let opening_proof_p_user_0 =
        kzg_bn254.open(&p_poly, omegas.element(index), expected_opening_value);

    // TO DO: add multiopening here. User 0 should both open the index 0 and index 1 of the polynomial p.

    // 5. User 0 verifies opening proof for their balance
    let verify = kzg_bn254.verify(
        expected_opening_value,
        omegas.element(index),
        p_commitment,
        opening_proof_p_user_0,
    );

    assert!(verify);
}
