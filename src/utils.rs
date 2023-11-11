use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial, DenseUVPolynomial};
use ark_std::rand::Rng;
use ark_std::UniformRand;

pub fn get_omega_domain<E: Pairing>(
    n: usize,
) -> (GeneralEvaluationDomain<E::ScalarField>, Vec<E::ScalarField>) {
    // Builds the domain consisting of n roots of unity in F
    let omegas = GeneralEvaluationDomain::<E::ScalarField>::new(n).unwrap();

    // Our omegas (domain of P(X)) in a vector that we will access later on
    let mut domain_elements: Vec<E::ScalarField> = vec![];
    for element in omegas.elements() {
        domain_elements.push(element);
    }
    (omegas, domain_elements)
}

pub fn generate_random_scalar_field_elements<E: Pairing>(
    rng: &mut impl Rng,
    n: usize,
) -> Vec<E::ScalarField> {
    // small utility method used for testing
    let mut p_evaluations = vec![];
    for i in 0..n {
        // P(omega^i) = random * i
        let eval = E::ScalarField::rand(rng) * E::ScalarField::from(i as u32);
        p_evaluations.push(eval);
    }
    p_evaluations
}

pub fn compute_evaluations_for_specific_omegas<E: Pairing>(
    omegas_indexes: Vec<usize>,
    omega_elements: &Vec<E::ScalarField>,
    p: &DensePolynomial<E::ScalarField>,
) -> Vec<<E as Pairing>::ScalarField> {
    // computes the evaluations of P(w^i) at specific indexes and stores them in a vector.
    // vec[i] is the evaluation of P(w^i) if i is in omegas_indexe else vec[i] is 0
    let mut evaluations = vec![];
    for (i, element) in omega_elements.iter().enumerate() {
        if omegas_indexes.contains(&i) {
            // at omega^2 and omega^3, we want to have P(omega^2) and P(omega^3)
            let eval = p.evaluate(&element);
            evaluations.push(eval);
        } else {
            evaluations.push(E::ScalarField::ZERO);
        }
    }
    evaluations
}

pub fn build_zero_polynomial<E: Pairing>(roots: &Vec<E::ScalarField>) -> DensePolynomial<<E as Pairing>::ScalarField> {
    // roots are the values at which the polynomial will be zero
    // (X - roots[0]) * (X - roots[1]) * ... * (X - roots[n])
    let mut polys = vec![];
    for root in roots {
        let poly = DensePolynomial::from_coefficients_vec(vec![*root * (-E::ScalarField::ONE), E::ScalarField::ONE]);
        polys.push(poly);
    }
    // multiply all the different polys together to get one single polynomial
    let mut zero_poly = polys[0].clone();
    for i in 1..polys.len() {
        zero_poly = &zero_poly * &polys[i];
    }
    zero_poly
}