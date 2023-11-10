mod kzg;
mod lagrange;

#[cfg(test)]
mod tests {
    use super::*;
    use kzg::KZG;
    use ark_bn254::{Bn254, Fr as F, G1Projective as G1, G2Projective as G2};
    use ark_poly::polynomial::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_poly::Polynomial;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use lagrange::lagrange_interpolate;
    
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
    fn lagrange() {
        lagrange_interpolate();
    }
}
