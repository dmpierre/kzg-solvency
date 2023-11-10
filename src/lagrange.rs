use ark_bn254::Fr;
use ark_r1cs_std::poly::evaluations::univariate::lagrange_interpolator::LagrangeInterpolator;
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    poly::domain::Radix2DomainVar,
    R1CSVar,
};
use ark_ff::{FftField, Field, One};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, UniformRand};
use ark_std::vec::Vec;

pub fn lagrange_interpolate() {
    let mut rng = test_rng();
    let poly = DensePolynomial::rand(15, &mut rng);
    let gen = Fr::get_root_of_unity(1 << 4).unwrap();
    assert_eq!(gen.pow(&[1 << 4]), Fr::one());

    let domain = Radix2DomainVar::new(
        gen,
        4, // 2^4 = 16
        FpVar::constant(Fr::GENERATOR),
    )
    .unwrap();

    // generate evaluations of `poly` on this domain
    let mut coset_point = domain.offset().value().unwrap();
    let mut oracle_evals = Vec::new();
    for _ in 0..(1 << 4) {
        oracle_evals.push(poly.evaluate(&coset_point));
        coset_point *= gen;
    }

    let interpolator = LagrangeInterpolator::new(
        domain.offset().value().unwrap(),
        domain.gen,
        domain.dim,
        oracle_evals,
    );

    // the point to evaluate at
    let interpolate_point = Fr::rand(&mut rng);

    let expected = poly.evaluate(&interpolate_point);
    let actual = interpolator.interpolate(interpolate_point);

    assert_eq!(actual, expected)
}
