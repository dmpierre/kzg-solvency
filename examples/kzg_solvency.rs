use std::time::Instant;

use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
use ark_poly::{polynomial::Polynomial, EvaluationDomain};
use ark_poly::{univariate::DensePolynomial, Evaluations};
use ark_std::Zero;
use ark_std::{test_rng, UniformRand};
use kzg_solvency::misc::{generate_random_balances, generate_users, greet};
use kzg_solvency::utils::build_zero_polynomial;
use kzg_solvency::utils::{compute_evaluations_for_specific_omegas, get_omega_domain};
use kzg_solvency::{kzg::KZG, lagrange::lagrange_interpolate};

fn main() {
    greet();

    // 1. Setup
    let mut rng = test_rng();
    let n = 100;
    println!("1. Starting setup with {} random balances and users", n);
    let balances = generate_random_balances(&mut rng, n);
    let users = generate_users(&mut rng, &balances);

    // Sampling a random tau and random generators g1 and g2
    let tau = F::rand(&mut rng);
    let g1 = G1::rand(&mut rng);
    let g2 = G2::rand(&mut rng);

    // 2. Generate witness tables
    // The logic of the witness table is based on section "Improving privacy and robustness with ZK-SNARKs" of https://vitalik.ca/general/2022/11/19/proof_of_solvency.html
    // Instantiating the witness tables over BN254. Should be working with other pairing groups.
    println!("2. Generating witness tables");
    let (p_witness, i_witness) = kzg_solvency::prover::generate_witness::<Bn254>(users).unwrap();

    // 3. Interpolate witness tables into polynomials. i.e. computing P(X) and I(X)
    println!("3. Computing lagrange interpolation for P(X) and I(X) from witness tables");
    let p_poly = lagrange_interpolate(&p_witness);
    let i_poly = lagrange_interpolate(&i_witness);
    let poly_degree = p_poly.degree();
    let i_degree = i_poly.degree();

    assert_eq!(poly_degree, i_degree);

    // 4. Initiating KZG and committing to polynomials P(X) and I(X)
    println!("4. KZG-committing to P(X) and I(X)");
    let mut kzg_bn254 = KZG::<Bn254>::new(g1, g2, poly_degree);
    kzg_bn254.setup(tau); // setup modifies in place the struct crs
    let p_commitment = kzg_bn254.commit(&p_poly);
    let i_commitment = kzg_bn254.commit(&i_poly);

    // 5. Generate opening proof for polynomial p at index `index_opened` - Constraint 1
    let index_opened = 2;
    println!(
        "5. -- Constraint 1 -- Starting example multi-opening proof generation for user at index {}",
        index_opened
    );
    let start = Instant::now();
    let k = n * 16; // This is n*16 because we have that P(X) has the same number of evaluations as I(X) (16 coeffs per user)
    let (omegas, omega_elements) = get_omega_domain::<Bn254>(k);
    let l_evaluations = compute_evaluations_for_specific_omegas::<Bn254>(
        vec![index_opened, index_opened + 1],
        &omega_elements,
        &p_poly,
    );
    let L = Evaluations::<F>::from_vec_and_domain(l_evaluations.clone(), omegas).interpolate();
    let Z = build_zero_polynomial::<Bn254>(&vec![
        omega_elements[index_opened],
        omega_elements[index_opened + 1],
    ]);
    let pi = kzg_bn254.multi_open(
        &p_poly,
        &L,
        vec![
            omega_elements[index_opened],
            omega_elements[index_opened + 1],
        ],
    );
    let duration = start.elapsed();
    println!(
        "  (Proved inclusion of (username, balance) at indexes ({}, {}) in {:.2}s))",
        index_opened,
        index_opened + 1,
        duration.as_secs_f64()
    );

    // 6. User verifies that the opening proof includes their username and balance
    let verify = kzg_bn254.verify_multi_open(p_commitment, pi, &Z, &L);
    assert!(verify);
    println!(
        "6. Multi opening proof for Constraint 1 verified to {}!",
        verify
    );

    // 7. Generate opening proof for constraint 2: I(ω^(16*x)) = 0. We need to enforce that I(X) vanishes for [ω^0, ω^16, ..., ω^112]
    println!("7. -- Constraint 2 -- Starting opening proof for I(ω^(16*x)) = 0 ");
    let start = Instant::now();
    let mut vanishing_omegas: Vec<F> = vec![];

    for i in 0..n {
        vanishing_omegas.push(omegas.element(16 * i));
    }

    let mut omega_elements: Vec<F> = vec![];
    for element in omegas.elements() {
        omega_elements.push(element);
    }

    // The evaluation of I(X) at the vanishing_omegas should be zero
    let mut l_evaluations = vec![];
    for (_, _) in omega_elements.iter().enumerate() {
        l_evaluations.push(F::zero());
    }

    // The expected opening value for constraint 1 is the evaluation of I(X) at the vanishing_omegas, which should be zero
    let L: DensePolynomial<F> =
        Evaluations::<F>::from_vec_and_domain(l_evaluations.clone(), omegas).interpolate();

    // Generate opening proof for constraint 1
    let opening_proof_constraint_1 = kzg_bn254.multi_open(&i_poly, &L, vanishing_omegas.clone());
    let duration = start.elapsed();
    println!(
        "  (Proved I(ω^(16*x)) = 0 constraint in {:.2}s))",
        duration.as_secs_f64()
    );

    // Build vanishing polynomial Z(X) in [(P(x) - Q(X)) / Z(X)]
    let Z = build_zero_polynomial::<Bn254>(&vanishing_omegas);

    // 8. User verifies opening proof for constraint 1 - expect evaluation L(X) = 0
    let verify = kzg_bn254.verify_multi_open(i_commitment, opening_proof_constraint_1, &Z, &L);
    println!(
        "8. Multi opening proof for Constraint 2 verified to {}!",
        verify
    );

    assert!(verify);

    // 9. Generate opening proof for constraint 3: I(ω^(16*x + 14) - P(ω^(2*x + 1) = 0.
    // The strategy is to open I(X) at ω^14 and P(X) at ω^1 and match the evaluations. Then, do the same for ω^30 and ω^3, etc.
    println!(
        "9. -- Constraint 3 -- Starting opening proof for I(ω^(16*x + 14) - P(ω^(2*x + 1) = 0 "
    );
    let start = Instant::now();
    // iterate over each user
    for i in 0..n {
        // Let's start by I(X)
        let opening = kzg_bn254.open(&i_poly, omega_elements[16 * i + 14], F::from(balances[i]));

        let encrypted_evaluation = kzg_bn254.g1 * F::from(balances[i]);

        let verify = kzg_bn254.verify_from_encrypted_y(
            encrypted_evaluation,
            omega_elements[16 * i + 14],
            i_commitment,
            opening,
        );

        assert!(verify);

        // Now let's do the same for P(X)
        let opening = kzg_bn254.open(&p_poly, omega_elements[2 * i + 1], F::from(balances[i]));
        let verify = kzg_bn254.verify_from_encrypted_y(
            encrypted_evaluation,
            omega_elements[2 * i + 1],
            p_commitment,
            opening,
        );

        assert!(verify);
    }

    let duration = start.elapsed();
    println!(
        "  (Proved I(ω^(16*x + 14) - P(ω^(2*x + 1) = 0 constraint in {:.2}s))",
        duration.as_secs_f64()
    );

    // 10. User should verify that the two opening proofs are true for all users and that the encrypted evaluation is the same for both proofs, 
    println!("10. Multi opening proof for Constraint 3 verified to true");

    // TO KEEP: Used for terminal pretty printing
    println!("");
}
