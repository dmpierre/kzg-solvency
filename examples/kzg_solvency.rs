use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
use ark_poly::{
    polynomial::Polynomial, univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
    Evaluations, GeneralEvaluationDomain,
};
use ark_std::{rand::Rng, test_rng, UniformRand, Zero};
use kzg_solvency::{
    kzg::KZG, lagrange::lagrange_interpolate, prover::User, utils::build_zero_polynomial,
};

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
    // TO DO: witness should do hashing for username and salt. Now it's just adding them together. Like a dummy hash.
    let (p_witness, i_witness) = kzg_solvency::prover::generate_witness(users).unwrap();

    // 3. Interpolate witness tables into polynomials
    let p_poly = lagrange_interpolate(&p_witness);
    let i_poly = lagrange_interpolate(&i_witness);

    let tau = F::rand(&mut rng);

    // TO DO: Why is it random?
    let g1 = G1::rand(&mut rng);
    let g2 = G2::rand(&mut rng);

    let poly_degree = p_poly.degree();
    let i_degree = i_poly.degree();

    assert_eq!(poly_degree, i_degree);

    let mut kzg_bn254 = KZG::<Bn254>::new(g1, g2, poly_degree);

    kzg_bn254.setup(tau); // setup modifies in place the struct crs
    let p_commitment = kzg_bn254.commit(&p_poly);
    let i_commitment = kzg_bn254.commit(&i_poly);

    // 4. Generate opening proof for polynomial p at index 1 (user 0 balance)
    let index = 1;

    let k = 7; // 2^7 = 128 which is the number of elements in each witness table
    let omegas = GeneralEvaluationDomain::<F>::new(1 << k).unwrap();

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

    // 6. Generate opening proof for constraint 1: I(ω^(16*x)) = 0. We need to enforce that I(X) vanishes for [ω^0, ω^16, ..., ω^112]
    let mut vanishing_omegas: Vec<F> = vec![];

    for i in 0..8 {
        vanishing_omegas.push(omegas.element(16 * i));
    }

    let mut omega_elements: Vec<F> = vec![];
    for element in omegas.elements() {
        omega_elements.push(element);
    }

    // The evaluation of I(X) at the vanishing_omegas should be zero
    let mut i_evaluations = vec![];
    for (_, _) in omega_elements.iter().enumerate() {
        i_evaluations.push(F::zero());
    }

    // The expected opening value for constraint 1 is the evaluation of I(X) at the vanishing_omegas, which should be zero
    let expected_opening_value: DensePolynomial<F> =
        Evaluations::<F>::from_vec_and_domain(i_evaluations.clone(), omegas).interpolate();

    // Generate opening proof for constraint 1
    let opening_proof_constraint_1 =
        kzg_bn254.multi_open(&i_poly, &expected_opening_value, vanishing_omegas.clone());

    // zero polynomial
    // Build denominator polynomial Z(X) in [(P(x) - Q(X)) / Z(X)]
    let Z = build_zero_polynomial::<Bn254>(&vanishing_omegas);

    // 7. User 0 verifies opening proof for constraint 1
    let verify = kzg_bn254.verify_multi_open(
        i_commitment,
        opening_proof_constraint_1,
        &Z,
        &expected_opening_value,
    );

    assert!(verify);

    // 8. Generate opening proof for constraint 2: I(ω^(16*x + 14) - P(ω^(2*x + 1) = 0.
    // This is a copy constraint and we need to enforce for each rotation
    // that is I(ω^14) - P(ω^1) = 0, I(ω^30) - P(ω^3) = 0, I(ω^46) - P(ω^5) = 0, ..., I(ω^126) - P(ω^15) = 0

    // build polynomial I(14ω) - P(ω)
    let i_coeffs = i_poly.coeffs();
    let mut stretched_coeffs = vec![F::zero(); 14 * i_coeffs.len()]; // Assuming F is your field type

    for (i, coeff) in i_coeffs.iter().enumerate() {
        stretched_coeffs[14 * i] = *coeff;
    }

    let stretched_poly = DensePolynomial::from_coefficients_vec(stretched_coeffs);

    let i_minus_p_poly = &stretched_poly - &p_poly;

    let poly_degree = i_minus_p_poly.degree();

    let mut kzg_bn254_2 = KZG::<Bn254>::new(g1, g2, poly_degree);
    kzg_bn254_2.setup(tau); // setup modifies in place the struct crs

    // Generate commitment for I(14X) - P(X)
    let i_minus_p_commitment = kzg_bn254_2.commit(&i_minus_p_poly);

    let expected_opening_value = F::zero();

    let open_proof_constraint_1_0 =
        kzg_bn254_2.open(&i_minus_p_poly, omegas.element(1), expected_opening_value);

    let verify = kzg_bn254_2.verify(
        expected_opening_value,
        omegas.element(1),
        i_minus_p_commitment,
        open_proof_constraint_1_0,
    );

    // TO DO: assert that the polynomial i_minus_p_poly is built correctly
    // TO DO: implement for each copy constraint

    assert!(verify);
}
