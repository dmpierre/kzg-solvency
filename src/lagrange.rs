use ark_bn254::Fr;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
};

pub fn lagrange_interpolate(evals: &Vec<Fr>) -> DensePolynomial<Fr> {
    // assert that the number of evaluations is a power of two
    let k = evals.len() as usize;
    let omegas = GeneralEvaluationDomain::<Fr>::new(k).unwrap();
    let lagrange: DensePolynomial<Fr> =
        Evaluations::<Fr>::from_vec_and_domain(evals.to_vec(), omegas).interpolate();
    lagrange
}
