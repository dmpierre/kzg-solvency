use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
use ark_poly::{polynomial::Polynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{rand::Rng, test_rng, UniformRand};
use kzg_solvency::misc::{generate_random_balances, generate_users, greet};
use kzg_solvency::utils::{get_omega_domain, compute_evaluations_for_specific_omegas};
use kzg_solvency::{kzg::KZG, lagrange::lagrange_interpolate, prover::User};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial,
    Evaluations
};
use ark_std::{Zero};
use kzg_solvency::{
    utils::build_zero_polynomial,
};

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

    let k = n * 16; // This is n*16 because we have that P(X) has the same number of evaluations as I(X) (16 coeffs per user)
    let (omegas, omega_elements) = get_omega_domain::<Bn254>(k);
    let omegas = GeneralEvaluationDomain::<F>::new(k).unwrap();
    let l_evaluations = compute_evaluations_for_specific_omegas::<Bn254>(vec![2, 3], &omega_elements, &p_poly);
    let L = Evaluations::<F>::from_vec_and_domain(l_evaluations.clone(), omegas).interpolate();
    let Z = build_zero_polynomial::<Bn254>(&vec![omega_elements[2], omega_elements[3]]);
    let pi = kzg_bn254.multi_open(&p_poly, &L, vec![omega_elements[2], omega_elements[3]]);

    // 5. User 0 verifies opening proof for their balance
    let verify = kzg_bn254.verify_multi_open(p_commitment, pi, &Z, &L);
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
