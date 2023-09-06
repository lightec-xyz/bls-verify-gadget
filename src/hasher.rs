use std::ops::Mul;

use ark_bls12_381::{Fq2, Bls12_381};
use ark_ec::{CurveGroup, CurveConfig, hashing::{HashToCurveError, curve_maps::wb::WBConfig}, bls12::{Bls12, Bls12Config}, pairing::Pairing};
use ark_ff::{Field, PrimeField, BitIteratorBE, MontFp, BitIteratorLE};
use ark_r1cs_std::{
    uint8::UInt8,
    prelude::Boolean,
    boolean,
    groups::bls12::{G2Var, G2AffineVar},
    groups::CurveVar,
    fields::{fp2::Fp2Var, fp::FpVar, FieldVar},
    ToConstraintFieldGadget,
    ToBytesGadget,
    ToBitsGadget,
    eq::EqGadget,
    R1CSVar, uint64::UInt64,
};

use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use hex::FromHex;

const MAX_DST_LENGTH: usize = 255;
const LEN_PER_BASE_ELEM: usize = 64; // ceil((381 + 128)/8)

/// quick and dirty hack from existing arkworks codes in algebra/ff and algebra/ec
/// for BLS over BLS12-381 only, as specified in ETH2, *not* intended for generic uses

type G2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2;
type BaseField = <G2 as CurveGroup>::BaseField;
type ConstraintF = <BaseField as Field>::BasePrimeField;
type FpVarDef = FpVar<<ark_bls12_381::Config as Bls12Config>::Fp>;
type Fp2VarDef = Fp2Var<<ark_bls12_381::Config as Bls12Config>::Fp2Config>;
type G2VarDef = G2Var<ark_bls12_381::Config>;
type G2AffineVarDef = G2AffineVar<ark_bls12_381::Config>;

pub struct DefaultFieldHasherWithCons {
    cs: ConstraintSystemRef<ConstraintF>,
    len_per_base_elem: usize,
    dst: Vec<UInt8<ConstraintF>>,
}

impl DefaultFieldHasherWithCons
{
    fn new(cs: ConstraintSystemRef<ConstraintF>, dst: &[UInt8<ConstraintF>]) -> Self {
        assert!(dst.len() <= MAX_DST_LENGTH, "DST too long");
        
        // The final output of `hash_to_field` will be an array of field
        // elements from TargetField, each of size `len_per_elem`.
        let len_per_base_elem = LEN_PER_BASE_ELEM;

        DefaultFieldHasherWithCons {
            cs: cs.clone(),
            len_per_base_elem,
            dst: dst.to_vec(),
        }
    }

    fn hash_to_field(&self, message: &[UInt8<ConstraintF>], count: usize) -> Vec<Fp2VarDef> {
        assert!(count == 2);

        let m = BaseField::extension_degree() as usize;
        assert!(m == 2);

        // The user imposes a `count` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes: usize = count * m * self.len_per_base_elem;
        let uniform_bytes = Self::expand(self, message, len_in_bytes);

        let mut output = Vec::with_capacity(count);
        let mut base_prime_field_elems = Vec::with_capacity(m);
        for i in 0..count {
            base_prime_field_elems.clear();
            for j in 0..m {
                let elm_offset = self.len_per_base_elem * (j + i * m);
                let constrainted_bytes = &uniform_bytes[elm_offset..][..self.len_per_base_elem];
                let mut c_bytes_le = constrainted_bytes.to_vec();
                c_bytes_le.reverse();

                let pos = ((ConstraintF::MODULUS_BIT_SIZE - 1) / 8) as usize;
                let (tail, head)
                    = c_bytes_le.split_at(c_bytes_le.len() - pos);
                let f_head: Vec<FpVarDef> = head.to_constraint_field().unwrap();
                let f_tail: Vec<FpVarDef> = tail.to_constraint_field().unwrap();

                // TODO clean up value move and clone()
                let fp = FpVarDef::constant(ConstraintF::from(256));
                let mut f = f_head[0].clone();

                let mut l = 0;
                while l < tail.len() {
                    f *= fp.clone();
                    l += 1;
                }

                f += f_tail[0].clone();

                base_prime_field_elems.push(f);
            }
            let fv = Fp2VarDef::new(base_prime_field_elems[0].clone(), base_prime_field_elems[1].clone());

            output.push(fv);
        }

        output
    }

    /// acording to https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd
    fn expand(&self, message: &[UInt8<ConstraintF>], len_in_bytes: usize) -> Vec<UInt8<ConstraintF>> {
        let b_len = 32;
        let ell = (len_in_bytes + b_len - 1) / b_len;
        assert!(ell <= 255, "The ratio of desired output to the output size of hash function is too large!");
        assert!(len_in_bytes <= 65535, "Length should be smaller than 2^16");

        let mut dst_prime = self.dst.clone();
        let dst_len_var = UInt8::<ConstraintF>::constant(dst_prime.len() as u8);
        dst_prime.push(dst_len_var);
        let dst_prime = dst_prime;

        let z_pad = UInt8::<ConstraintF>::constant_vec(&[0u8; 64]);

        let lib_str: [u8; 2] = (len_in_bytes as u16).to_be_bytes();
        let lib_str_var = UInt8::<ConstraintF>::new_witness_vec(self.cs.clone(), &lib_str).unwrap();

        let mut msg_prime = z_pad.clone();
        msg_prime.extend_from_slice(message);
        msg_prime.extend_from_slice(&lib_str_var);
        msg_prime.push(UInt8::constant(0u8));
        msg_prime.extend_from_slice(&dst_prime);
        let b0: Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&msg_prime).unwrap().to_bytes().unwrap();

        let mut data = b0.clone();
        data.push(UInt8::constant(1u8));
        data.extend_from_slice(&dst_prime);
        let b1: Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&data).unwrap().to_bytes().unwrap();

        let mut ret = b1.clone();
        let mut last_b = b1.clone();
        for i in 2..(ell+1) {
            let mut bx = std::iter::zip(b0.iter(), last_b.iter())
                .into_iter()
                .map(|(a, b)| a.xor(b).unwrap())
                .collect::<Vec<UInt8<ConstraintF>>>();
            bx.push(UInt8::constant(i as u8));
            bx.extend_from_slice(&dst_prime);
            let bi: Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&bx).unwrap().to_bytes().unwrap();
            ret.extend_from_slice(&bi);

            last_b = bi.clone();
        }

        assert!(ret.len() == len_in_bytes);

        ret
    }

}

struct DensePolynomialVar {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<Fp2VarDef>,
}

impl DensePolynomialVar {
    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_slice(coeffs: &[Fp2VarDef]) -> Self {
        Self::from_coefficients_vec(coeffs.to_vec())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_vec(coeffs: Vec<Fp2VarDef>) -> Self {
        Self { coeffs }
    }

    /// Evaluates `self` at the given `point` and just gives you the gadget for
    /// the result. Caution for use in holographic lincheck: The output has
    /// 2 entries in one matrix
    pub fn evaluate(&self, point: &Fp2VarDef) -> Result<Fp2VarDef, SynthesisError> {
        let mut result = Fp2VarDef::zero();
        // current power of point
        let mut curr_pow_x = Fp2VarDef::one();
        for i in 0..self.coeffs.len() {
            let term = &curr_pow_x * &self.coeffs[i];
            result += &term;
            curr_pow_x *= point;
        }

        Ok(result)
    }
}

pub struct CurveMapperWithCons <'a>{
    cs: ConstraintSystemRef<ConstraintF>,
    COEFF_A: Fp2VarDef,
    COEFF_B: Fp2VarDef,
    ZETA: Fp2VarDef,
    C1: &'a str,
    C2: Fp2VarDef,
    C3: Fp2VarDef,
    C4: Fp2VarDef,
    C5: Fp2VarDef,
}

impl CurveMapperWithCons<'_>
{
    fn new(cs: ConstraintSystemRef<ConstraintF>) -> Result<Self, HashToCurveError> {
        Ok(CurveMapperWithCons{
            cs: cs.clone(),
            // see section 8.8.2 of RFC 9380 for below values
            COEFF_A: Fp2VarDef::constant(Fq2::new(MontFp!("0"), MontFp!("240"))),
            COEFF_B: Fp2VarDef::constant(Fq2::new(MontFp!("1012"), MontFp!("1012"))),
            ZETA: Fp2VarDef::constant(Fq2::new(MontFp!("-2"), MontFp!("-1"))),

            //    Constants:
            //    1. c1 = (q - 9) / 16            # Integer arithmetic
            //    2. c2 = sqrt(-1)
            //    3. c3 = sqrt(c2)
            //    4. c4 = sqrt(Z^3 / c3)
            //    5. c5 = sqrt(Z^3 / (c2 * c3))
            C1: "2a437a4b8c35fc74bd278eaa22f25e9e2dc90e50e7046b466e59e49349e8bd050a62cfd16ddca6ef53149330978ef011d68619c86185c7b292e85a87091a04966bf91ed3e71b743162c338362113cfd7ced6b1d76382eab26aa00001c718e3",
            C2: Fp2VarDef::constant(Fq2::new(MontFp!("0"), MontFp!("1"))),
            C3: Fp2VarDef::constant(Fq2::new(MontFp!("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
                MontFp!("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"))),
            C4: Fp2VarDef::constant(Fq2::new(MontFp!("1015919005498129635886032702454337503112659152043614931979881174103627376789972962005013361970813319613593700736144"),
                MontFp!("1244231661155348484223428017511856347821538750986231559855759541903146219579071812422210818684355842447591283616181"))),
            C5: Fp2VarDef::constant(Fq2::new(MontFp!("1637752706019426886789797193293828301565549384974986623510918743054325021588194075665960171838131772227885159387073"),
                MontFp!("2356393562099837637521906572659114847248791943663835535137223682689832134851362912628461394915339516530489788841108"))),
        })
    }

    fn map_to_curve(&self, u: Fp2VarDef) -> G2VarDef {
        let point_on_isogenious_curve = self.map_to_curve_9mod16(u).unwrap();
        self.isogeny_map(point_on_isogenious_curve).unwrap()
    }

    // match point.xy() {
    //     Some((x, y)) => {
    //         let x_num = DensePolynomial::from_coefficients_slice(self.x_map_numerator);
    //         let x_den = DensePolynomial::from_coefficients_slice(self.x_map_denominator);

    //         let y_num = DensePolynomial::from_coefficients_slice(self.y_map_numerator);
    //         let y_den = DensePolynomial::from_coefficients_slice(self.y_map_denominator);

    //         let mut v: [BaseField<Domain>; 2] = [x_den.evaluate(x), y_den.evaluate(x)];
    //         batch_inversion(&mut v);
    //         let img_x = x_num.evaluate(x) * v[0];
    //         let img_y = (y_num.evaluate(x) * y) * v[1];
    //         Ok(Affine::<Codomain>::new_unchecked(img_x, img_y))
    //     },
    //     None => Ok(Affine::identity()),
    // }
    fn isogeny_map(&self, point: G2VarDef) -> Result<G2VarDef, HashToCurveError> {
        let is_infinity: Boolean<ConstraintF> = point.z.is_zero().unwrap();
        let (x, y) = to_affine_unchecked(point);

        let isogeny_map = <ark_bls12_381::g2::Config as WBConfig>::ISOGENY_MAP;

        let x_num_var = DensePolynomialVar::from_coefficients_slice(
            &[Fp2VarDef::constant(isogeny_map.x_map_numerator[0]),
            Fp2VarDef::constant(isogeny_map.x_map_numerator[1]),
            Fp2VarDef::constant(isogeny_map.x_map_numerator[2]),
            Fp2VarDef::constant(isogeny_map.x_map_numerator[3]),]
        );

        let x_den_var = DensePolynomialVar::from_coefficients_slice(
            &[Fp2VarDef::constant(isogeny_map.x_map_denominator[0]),
            Fp2VarDef::constant(isogeny_map.x_map_denominator[1]),
            Fp2VarDef::constant(isogeny_map.x_map_denominator[2]),]
        );

        let y_num_var = DensePolynomialVar::from_coefficients_slice(
            &[Fp2VarDef::constant(isogeny_map.y_map_numerator[0]),
            Fp2VarDef::constant(isogeny_map.y_map_numerator[1]),
            Fp2VarDef::constant(isogeny_map.y_map_numerator[2]),
            Fp2VarDef::constant(isogeny_map.y_map_numerator[3]),]
        );

        let y_den_var = DensePolynomialVar::from_coefficients_slice(
            &[Fp2VarDef::constant(isogeny_map.y_map_denominator[0]),
            Fp2VarDef::constant(isogeny_map.y_map_denominator[1]),
            Fp2VarDef::constant(isogeny_map.y_map_denominator[2]),
            Fp2VarDef::constant(isogeny_map.y_map_denominator[3]),]
        );

        let x_den_at_x = x_den_var.evaluate(&x).unwrap();
        let x_den_at_x_inv = x_den_at_x.inverse().unwrap();

        let y_den_at_x = y_den_var.evaluate(&x).unwrap();
        let y_den_at_x_inv = y_den_at_x.inverse().unwrap();

        let x_num_at_x = x_num_var.evaluate(&x).unwrap();
        let y_num_at_x = y_num_var.evaluate(&x).unwrap();

        let img_x = x_num_at_x * x_den_at_x_inv;
        let img_y = (y_num_at_x * &y) * y_den_at_x_inv;

        let projective = G2VarDef::new(img_x, img_y, Fp2VarDef::one());
        let zero = G2VarDef::new(Fp2VarDef::zero(), Fp2VarDef::zero(), Fp2VarDef::zero());
        let projective: G2VarDef = is_infinity.select(&zero, &projective).unwrap();

        Ok(projective)
    }

    /// use https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-G.2.3
    /// it is optimized for 9 mod 16 (isogeneous to BLS12-381 G2)
    fn map_to_curve_9mod16(&self, u: Fp2VarDef) -> Result<G2VarDef, HashToCurveError> {
        //    Input: u, an element of F.
        //    Output: (xn, xd, yn, yd) such that (xn / xd, yn / yd) is a
        //            point on the target curve.

        let Z = &self.ZETA;
        let A = &self.COEFF_A;
        let B = &self.COEFF_B;
        //    Steps:
        //    1.  tv1 = u^2
        let tv1 = u.square().unwrap();//(1, 0)
        //    2.  tv3 = Z * tv1
        let tv3 = Z * &tv1;
        //    3.  tv5 = tv3^2
        let tv5 = tv3.square().unwrap();
        //    4.   xd = tv5 + tv3
        let xd = &tv5 + &tv3;
        //    5.  x1n = xd + 1
        let x1n = &xd + Fp2VarDef::one();
        //    6.  x1n = x1n * B
        let x1n = x1n * B;
        //    7.   xd = -A * xd
        let xd = A.negate().unwrap() * &xd;
        //    8.   e1 = xd == 0
        let e1 = self.is_zero(&xd);
        //    9.   xd = CMOV(xd, Z * A, e1)   # If xd == 0, set xd = Z * A
        let xd = self.cmov(&xd, &(Z * A), e1);
        //    10. tv2 = xd^2
        let tv2 = xd.square().unwrap();
        //    11. gxd = tv2 * xd              # gxd == xd^3
        let gxd = &tv2 * &xd;
        //    12. tv2 = A * tv2
        let tv2 = A * tv2;
        //    13. gx1 = x1n^2
        //    14. gx1 = gx1 + tv2             # x1n^2 + A * xd^2
        let gx1 = x1n.square().unwrap() + tv2;
        //    15. gx1 = gx1 * x1n             # x1n^3 + A * x1n * xd^2
        let gx1 = gx1 * &x1n;
        //    16. tv2 = B * gxd
        let tv2 = B * &gxd;
        //    17. gx1 = gx1 + tv2             # x1n^3 + A * x1n * xd^2 + B * xd^3
        let gx1 = gx1 + tv2;
        //    18. tv4 = gxd^2
        let tv4 = gxd.square().unwrap();
        //    19. tv2 = tv4 * gxd             # gxd^3
        let tv2 = &tv4 * &gxd;
        //    20. tv4 = tv4^2                 # gxd^4
        let tv4 = tv4.square().unwrap();
        //    21. tv2 = tv2 * tv4             # gxd^7
        let tv2 = tv2 * &tv4;
        //    22. tv2 = tv2 * gx1             # gx1 * gxd^7
        let tv2 = tv2 * &gx1;
        //    23. tv4 = tv4^2                 # gxd^8
        let tv4 = tv4.square().unwrap();
        //    24. tv4 = tv2 * tv4             # gx1 * gxd^15
        let tv4 = &tv2 * tv4;
        //    25.   y = tv4^c1                # (gx1 * gxd^15)^((q - 9) / 16)
        let y = self.pow(&tv4, self.C1);
        //    26.   y = y * tv2               # This is almost sqrt(gx1)
        let y = y * tv2;
        //    27. tv4 = y * c2                # check the four possible sqrts
        let tv4 = &y * &self.C2;
        //    28. tv2 = tv4^2
        let tv2 = tv4.square().unwrap();
        //    29. tv2 = tv2 * gxd
        let tv2 = tv2 * &gxd;
        //    30.  e2 = tv2 == gx1
        let e2 = tv2.is_eq(&gx1).unwrap();
        //    31.   y = CMOV(y, tv4, e2)
        let y = self.cmov(&y, &tv4, e2);
        //    32. tv4 = y * c3
        let tv4 = &y * &self.C3;
        //    33. tv2 = tv4^2
        let tv2 = tv4.square().unwrap();
        //    34. tv2 = tv2 * gxd
        let tv2 = tv2 * &gxd;
        //    35.  e3 = tv2 == gx1
        let e3 = tv2.is_eq(&gx1).unwrap();
        //    36.   y = CMOV(y, tv4, e3)
        let y = self.cmov(&y, &tv4, e3);
        //    37. tv4 = tv4 * c2
        let tv4 = tv4 * &self.C2;
        //    38. tv2 = tv4^2
        //    39. tv2 = tv2 * gxd
        let tv2 = tv4.square().unwrap() * &gxd;
        //    40.  e4 = tv2 == gx1
        let e4 = tv2.is_eq(&gx1).unwrap();
        //    41.   y = CMOV(y, tv4, e4)      # if x1 is square, this is its sqrt
        let y = self.cmov(&y, &tv4, e4);
        //    42. gx2 = gx1 * tv5
        //    43. gx2 = gx2 * tv3             # gx2 = gx1 * Z^3 * u^6
        let gx2 = &gx1 * tv5 * &tv3;
        //    44. tv5 = y * tv1
        let tv5 = &y * tv1;
        //    45. tv5 = tv5 * u               # This is almost sqrt(gx2)
        let tv5 = tv5 * &u;
        //    46. tv1 = tv5 * c4              # check the four possible sqrts
        let tv1 = &tv5 * &self.C4;
        //    47. tv4 = tv1 * c2
        let tv4 = &tv1 * &self.C2;
        //    48. tv2 = tv4^2
        //    49. tv2 = tv2 * gxd
        let tv2 = tv4.square().unwrap() * &gxd;
        //    50.  e5 = tv2 == gx2
        let e5 = tv2.is_eq(&gx2).unwrap();
        //    51. tv1 = CMOV(tv1, tv4, e5)
        let tv1 = self.cmov(&tv1, &tv4, e5);
        //    52. tv4 = tv5 * c5
        let tv4 = tv5 * &self.C5;
        //    53. tv2 = tv4^2
        //    54. tv2 = tv2 * gxd
        let tv2 = tv4.square().unwrap() * &gxd;
        //    55.  e6 = tv2 == gx2
        let e6 = tv2.is_eq(&gx2).unwrap();
        //    56. tv1 = CMOV(tv1, tv4, e6)
        let tv1 = self.cmov(&tv1, &tv4, e6);
        //    57. tv4 = tv4 * c2
        let tv4 = tv4 * &self.C2;
        //    58. tv2 = tv4^2
        //    59. tv2 = tv2 * gxd
        let tv2 = tv4.square().unwrap() * &gxd;
        //    60.  e7 = tv2 == gx2
        let e7 = tv2.is_eq(&gx2).unwrap();
        //    61. tv1 = CMOV(tv1, tv4, e7)
        let tv1 = self.cmov(&tv1, &tv4, e7);
        //    62. tv2 = y^2
        //    63. tv2 = tv2 * gxd
        let tv2 = y.square().unwrap() * gxd;
        //    64.  e8 = tv2 == gx1
        let e8 = tv2.is_eq(&gx1).unwrap();
        //    65.   y = CMOV(tv1, y, e8)      # choose correct y-coordinate
        let y = self.cmov(&tv1, &y, e8.clone());
        //    66. tv2 = tv3 * x1n             # x2n = x2n / xd = Z * u^2 * x1n / xd
        let tv2 = tv3 * &x1n;
        //    67.  xn = CMOV(tv2, x1n, e8)    # choose correct x-coordinate
        let xn = self.cmov(&tv2, &x1n, e8);
        //    68.  e9 = sgn0(u) == sgn0(y)    # Fix sign of y
        let sgn0_u = self.sgn0(&u);
        let sgn0_y = self.sgn0(&y);
        let e9 = sgn0_u.is_eq(&sgn0_y).unwrap();
        //    69.   y = CMOV(-y, y, e9)
        let y_neg = y.negate().unwrap();
        let y = self.cmov(&y_neg, &y, e9);

        //    70. return (xn, xd, y, 1)
        // unfortuantely the AffineVar::new is private, this is supposed to protect AffineVar.is_infinity
        // let affine_x = &xn * &xd.inverse().unwrap();
        // let affine_y = y.clone();

        to_projective_short(xd, xn, y)
    }

    /// based on RFC 9380 (draft ver 11) definition:
    /// CMOV(a, b, c): If c is False, CMOV returns a, otherwise it returns b.
    fn cmov(&self, f: &Fp2VarDef, t: &Fp2VarDef, cond: Boolean<ConstraintF>) -> Fp2VarDef {
        cond.select(t, f).unwrap()
    }

    fn is_zero(&self, v: &Fp2VarDef) -> Boolean<ConstraintF> {
        v.is_eq(&Fp2VarDef::zero()).unwrap()
    }

    // the sgn0_m_eq_2 as defined in section 4.2 (draft ver 11)
    fn sgn0(&self, v: &Fp2VarDef) -> Boolean<ConstraintF> {
        let c0_bits = v.c0.to_bits_le().unwrap();
        let c1_bits = v.c1.to_bits_le().unwrap();

        let sign_0: Boolean<ConstraintF> = c0_bits[0].clone();
        let zero_0: Boolean<ConstraintF> = v.c0.is_eq(&FpVarDef::zero()).unwrap();
        let sign_1: Boolean<ConstraintF> = c1_bits[0].clone();

        let r = zero_0.and(&sign_1).unwrap();
        sign_0.or(&r).unwrap()
    }

    fn pow(&self, v: &Fp2VarDef, exp: &str) -> Fp2VarDef {
        let mut exp_u8 = <Vec<u8>>::from_hex(exp).unwrap();
        exp_u8.reverse();
        let exp_cons: Vec<UInt8<ConstraintF>> = UInt8::<ConstraintF>::constant_vec(exp_u8.as_ref());
        let exp_bits: Vec<Boolean<ConstraintF>> = exp_cons.to_bits_be().unwrap();

        let one = Fp2VarDef::one();
        let mut r = one.clone();
        for bit in exp_bits.into_iter() {
            // println!("bit: {}", bit.value().unwrap());
            r = r.square().unwrap();
            let tv = bit.select(v, &one).unwrap();
            r *= tv;
        }

        r
    }
}

fn to_projective_short(xd: Fp2VarDef, xn: Fp2VarDef, y: Fp2VarDef) -> Result<G2VarDef, HashToCurveError> {
    // yd is Fp2VarDef::one() so simplified
    let xd3 = &xd.square().unwrap() * &xd;
    Ok(G2VarDef::new(xn * &xd, y * xd3, xd))
}

// fn to_projective(xd: Fp2VarDef, xn: Fp2VarDef, yn: Fp2VarDef, yd: Fp2VarDef) -> Result<G2VarDef, HashToCurveError> {
//     // To convert (xn, xd, yn, yd) to Jacobian projective coordinates,
//     // compute (X', Y', Z') = (xn * xd * yd^2, yn * yd^2 * xd^3, xd * yd).
//     let xd3 = &xd.square().unwrap() * &xd;
//     let yd2 = yd.clone().square().unwrap();
//     Ok(G2VarDef::new(xn * &xd * &yd2, yn * yd2 * xd3, xd * yd))
// }

fn to_affine_unchecked(point: G2VarDef) -> (Fp2VarDef, Fp2VarDef) {
    let x = &point.x;
    let y = &point.y;
    let z = &point.z;

    // A point (X', Y', Z') in Jacobian projective coordinates corresponds to the
    // affine point (x, y) = (X' / Z'^2, Y' / Z'^3)
    let z_inv = z.inverse().unwrap_or_else(|_| Fp2VarDef::zero());
    let z_inv_2 = z_inv.square().unwrap();
    let z_inv_3 = &z_inv_2 * z_inv;

    let x = x * z_inv_2;
    let y = y * z_inv_3;
    (x, y)
}

pub struct MapToCurveHasherWithCons<'a>
{
    field_hasher: DefaultFieldHasherWithCons,
    curve_mapper: CurveMapperWithCons<'a>,
    // PSI_X: Fp2VarDef,
    // PSI_Y: Fp2VarDef,
    // PSI_2_X: Fp2VarDef,
}

impl MapToCurveHasherWithCons<'_>
{
    // // PSI_X = 1/(u+1)^((p-1)/3)
    // const P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
    //     MontFp!("0"),
    //     MontFp!("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
    // );

    // // PSI_Y = 1/(u+1)^((p-1)/2)
    // const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    //     MontFp!("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
    //     MontFp!("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257")
    // );

    // // PSI_2_X = (u+1)^((1-p^2)/3) { also = 1 / 2^((p - 1) / 3) }
    // const DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
    //     MontFp!("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436"),
    //     MontFp!("0")
    // );

    fn new(cs: ConstraintSystemRef<ConstraintF>, domain: &[UInt8<ConstraintF>]) -> Result<Self, HashToCurveError> {
        let field_hasher = DefaultFieldHasherWithCons::new(cs.clone(), domain);
        let curve_mapper = CurveMapperWithCons::new(cs.clone())?;

        // let px: Fp2VarDef = Fp2VarDef::constant(Self::P_POWER_ENDOMORPHISM_COEFF_0);
        // let py: Fp2VarDef = Fp2VarDef::constant(Self::P_POWER_ENDOMORPHISM_COEFF_1);
        // let p2x: Fp2VarDef = Fp2VarDef::constant(Self::DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0);
        Ok(MapToCurveHasherWithCons {
                field_hasher,
                curve_mapper,
                // PSI_X: px,
                // PSI_Y: py,
                // PSI_2_X: p2x,
            })
        }

    // Produce a hash of the message, using the hash to field and map to curve
    // traits. This uses the IETF hash to curve's specification for Random
    // oracle encoding (hash_to_curve) defined by combining these components.
    // See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3
    fn hash(&self, msg: &[UInt8<ConstraintF>]) -> Result<G2VarDef, HashToCurveError> {
        // IETF spec of hash_to_curve, from hash_to_field and map_to_curve
        // sub-components
        // 1. u = hash_to_field(msg, 2)
        // 2. Q0 = map_to_curve(u[0])
        // 3. Q1 = map_to_curve(u[1])
        // 4. R = Q0 + Q1              # Point addition
        // 5. P = clear_cofactor(R)
        // 6. return P

        let rand_field_elems = self.field_hasher.hash_to_field(msg, 2);

        let rand_curve_elem_0 = self.curve_mapper.map_to_curve(rand_field_elems[0].clone());
        let rand_curve_elem_1 = self.curve_mapper.map_to_curve(rand_field_elems[1].clone());

        let rand_curve_elem = rand_curve_elem_0 + rand_curve_elem_1;

        let rand_subgroup_elem = self.clear_cofactor2(&rand_curve_elem);

        Ok(rand_subgroup_elem)
    }

    // slow implementation, FIXME
    fn clear_cofactor2(&self, point: &G2VarDef) -> G2VarDef {
        // value from section 8.8.2 of RFC 9380 (draft version 11)
        let h_eff = "0bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551";
        let mut h_eff_u8 = <[u8; 80]>::from_hex(h_eff).unwrap();
        h_eff_u8.reverse();
        let h_eff_var = UInt8::<ConstraintF>::constant_vec(&h_eff_u8);
        let mut h_eff_bits = h_eff_var.to_bits_be().unwrap();
        h_eff_bits.reverse();
        point.scalar_mul_le(h_eff_bits.iter()).unwrap()
    }

    // based on Appendix G.4 of RFC 9380 (draft ver 11)
    // this should be much more efficient that clear_cofactor2 implementation
    // (scalar multiplication by u64 for twice v.s. by u640 for h_eff)
    // however, the psi2 function output is not on curve, thus panic FIXME
    // fn clear_cofactor(&self, point: &G2VarDef) -> G2VarDef {
    //     // 1.  t1 = c1 * P
    //     let c = ark_bls12_381::Config::X[0];
    //     let c_var = UInt64::<ConstraintF>::constant(c);
    //     let c_bits = c_var.to_bits_le();
    //     let t1 = point.scalar_mul_le(c_bits.iter()).unwrap().negate().unwrap();
    //     // 2.  t2 = psi(P)
    //     let t2: G2VarDef = self.psi(point.clone());
    //     // 3.  t3 = 2 * P
    //     let t3: G2VarDef = point.double().unwrap();
    //     // 4.  t3 = psi2(t3)
    //     let t3 = self.psi2(t3);
    //     // 5.  t3 = t3 - t2
    //     let t3 = t3 - &t2;
    //     // 6.  t2 = t1 + t2
    //     let t2: G2VarDef = &t1 + t2;
    //     // 7.  t2 = c1 * t2
    //     let t2 = t2.scalar_mul_le(c_bits.iter()).unwrap().negate().unwrap();
    //     // 8.  t3 = t3 + t2
    //     // 9.  t3 = t3 - t1
    //     let t3 = t3 + t2 - t1;
    //     // 10.  Q = t3 - P
    //     // 11. return Q
    //     t3 - point
    // }

    // fn frobenius(x: Fp2VarDef) -> Fp2VarDef {
    //     Fp2VarDef::new(x.c0.clone(), x.c1.negate().unwrap())
    // }

    // fn psi(&self, point: G2VarDef) -> G2VarDef {
    //     let (xn, yn) = to_affine_unchecked(point);
    //     let qxn = &self.PSI_X * Self::frobenius(xn);
    //     // frobenius of one() is still one(), so skip qxd and qyd
    //     let qyn = &self.PSI_Y * Self::frobenius(yn);

    //     G2VarDef::new(qxn, qyn, Fp2VarDef::one())
    // }

    // fn psi2(&self, point: G2VarDef) -> G2VarDef {
    //     let (xn, yn) = to_affine_unchecked(point);
    //     let qxn = &self.PSI_2_X * xn;
    //     let qyn = yn.negate().unwrap();

    //     G2VarDef::new(qxn, qyn, Fp2VarDef::one())
    // }
}

pub fn hash_to_g2_with_cons(cs: ConstraintSystemRef<ConstraintF>, message: &[UInt8<ConstraintF>]) -> G2VarDef {
        
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let domain_var:  Vec<UInt8<ConstraintF>> = UInt8::<ConstraintF>::constant_vec(domain);

    let curve_hasher = MapToCurveHasherWithCons
    ::new(cs, &domain_var)
    .unwrap();

    curve_hasher.hash(message).unwrap()
}

#[cfg(test)]
mod test {
    use std::ops::Mul;

    use ark_bls12_381::{Fq2, FqConfig, g2, G2Affine, G2Projective};
    use ark_ec::{CurveGroup, CurveConfig, AffineRepr};
    use ark_ec::hashing::curve_maps::wb::WBMap;
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ff::{Field, MontFp, BitIteratorLE};
    use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
    use ark_r1cs_std::{uint8::UInt8, fields::FieldVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use hex::FromHex;
    use sha2::Sha256;
    use ark_std::{One, Zero};
    use num_bigint::BigUint;
    use ark_ff::MontConfig;
    use ark_ec::Group;
    use ark_r1cs_std::groups::CurveVar;
    use ark_ff::PrimeField;

    use crate::hasher::MapToCurveHasherWithCons;

    use super::{DefaultFieldHasherWithCons, ConstraintF, CurveMapperWithCons, Fp2VarDef, FpVarDef, G2VarDef, hash_to_g2_with_cons, G2};

    #[test]
    fn compute_constants() {
        // computes the constants c1~c5 according to Appendix G.2.3 (darft version 11 of RFC 9380)
        let A = Fq2::new(MontFp!("0"), MontFp!("240"));
        let B = Fq2::new(MontFp!("1012"), MontFp!("1012"));
        let Z = Fq2::new(MontFp!("-2"), MontFp!("-1"));

        let p: &BigUint = &FqConfig::MODULUS.into();
        println!("p: {}", p);

        let q: &BigUint = &p.mul(p);
        println!("q: {}", q.to_str_radix(16));

        let c1 = q - 9u8;
        println!("q - 9: {}", c1.to_str_radix(16));

        let c1: BigUint = c1 >> 4;
        println!("c1: {}", c1.to_str_radix(16));

        let mut one: Fq2 = Fq2::one();
        one.neg_in_place();
        let minus_one = one;
        let c2: Fq2 = minus_one.sqrt().unwrap();
        println!("c2: {}, {}", c2.c0, c2.c1);

        let c3 = c2.sqrt().unwrap();
        println!("c3: {}, {}", c3.c0, c3.c1);

        let z3 = Z.square() * Z;

        let c4 = z3 * c3.inverse().unwrap();
        let c4 = c4.sqrt().unwrap();
        println!("c4: {}, {}", c4.c0, c4.c1);

        let c5 = c2 * c3;
        let c5 = c5.inverse().unwrap();
        let c5 = z3 * c5;
        let c5 = c5.sqrt().unwrap();
        println!("c5: {}, {}", c5.c0, c5.c1);

        assert_eq!(z3, c5.square() * c2 * c3);
        assert_eq!(z3, c4.square() * c3);
        assert_eq!(c2, c3.square());
        assert_eq!(c2.square(), Fq2::new(MontFp!("-1"), MontFp!("0")));

        // for cofactor clearing
        let two = Fq2::new(MontFp!("2"), MontFp!("0"));
        let two_inv = two.inverse().unwrap();
        let exp = (p - 1u8) / 3u8;
        let exp_u64s: Vec<u64> = exp.to_u64_digits();
        let cc = two_inv.pow(exp_u64s);
        println!("cc: {}", cc);

    }

    #[test]
    fn test_expand() {
        // let's use this test vector from the ../tests folder
        // "DST_prime": "412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a23620",
        // "len_in_bytes": "0x20",
        // "msg": "abc",
        // "msg_prime": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000616263002000412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a23620",
        // "uniform_bytes": "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12"

        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let msg = "abc";
        let dst = <[u8; 32]>::from_hex("412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a236").unwrap();
        let dst_var = UInt8::<ConstraintF>::new_witness_vec(cs.clone(), dst.as_ref()).unwrap();
        let hasher = DefaultFieldHasherWithCons {
            cs: cs.clone(),
            len_per_base_elem: 32,
            dst: dst_var,
        };

        let msg_var = UInt8::<ConstraintF>::new_witness_vec(cs.clone(), msg.as_ref()).unwrap();
        let exp = hasher.expand(&msg_var, 32);
        let expanded_bytes = exp.iter().map(|x| x.value().unwrap()).collect::<Vec<u8>>();
        let expected_bytes = <[u8; 32]>::from_hex("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12").unwrap();

        assert_eq!(expanded_bytes, expected_bytes);
    }

    #[test]
    fn test_expand_long() {
        // let's use this test vector from the ../tests folder
        // "DST_prime": "412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a23620",
        // "len_in_bytes": "0x80",
        // "msg": "abc",
        // "msg_prime": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000616263008000412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a23620",
        // "uniform_bytes": "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267"

        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let msg = "abc";
        let dst = <[u8; 32]>::from_hex("412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a236").unwrap();
        let dst_var = UInt8::<ConstraintF>::new_witness_vec(cs.clone(), dst.as_ref()).unwrap();
        let hasher = DefaultFieldHasherWithCons {
            cs: cs.clone(),
            len_per_base_elem: 64,
            dst: dst_var,
        };

        let msg_var = UInt8::<ConstraintF>::new_witness_vec(cs.clone(), msg.as_ref()).unwrap();
        let exp = hasher.expand(&msg_var, 128);
        let expanded_bytes = exp.iter().map(|x| x.value().unwrap()).collect::<Vec<u8>>();
        let expected_bytes = <[u8; 128]>::from_hex("1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267").unwrap();

        assert_eq!(expanded_bytes, expected_bytes);
    }

    #[test]
    fn test_hash_to_field() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let msg = "abc";
        let msg_var = UInt8::new_witness_vec(cs.clone(), msg.as_ref()).unwrap();
        let dst = <[u8; 32]>::from_hex("412717974da474d0f8c420f320ff81e8432adb7c927d9bd082b4fb4d16c0a236").unwrap();
        let dst_var = UInt8::<ConstraintF>::new_witness_vec(cs.clone(), dst.as_ref()).unwrap();

        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fq2>>::new(&dst);
        let hashed: Vec<Fq2> = hasher.hash_to_field(msg.as_ref(), 2);
        println!("{}\n{}\n\n", hashed[0], hashed[1]);

        let hasher_cons = DefaultFieldHasherWithCons {
            cs: cs.clone(),
            len_per_base_elem: 64,
            dst: dst_var,
        };
        let hashed_2 = hasher_cons
            .hash_to_field(&msg_var, 2)
            .iter()
            .map(|x| x.value().unwrap())
            .collect::<Vec<Fq2>>();

        println!("{}\n{}\n\n", hashed_2[0], hashed_2[1]);
        assert_eq!(hashed, hashed_2);
    }

    #[test]
    fn test_pow() {
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let mapper_cons = CurveMapperWithCons::new(cs).unwrap();

        let one_var = Fp2VarDef::one();
        let two_var = &one_var + &one_var;
        let power = mapper_cons.pow(&two_var, "000014");
        println!("c0 {}, c1 {}", power.c0.value().unwrap(), power.c1.value().unwrap());

        let expected = Fp2VarDef::constant(Fq2::new(MontFp!("1048576"), MontFp!("0")));
        assert_eq!(power.value().unwrap(), expected.value().unwrap());

        // let's play with Euler's theorem for quadric extension field: q = p^2, x^(q-1) = 1 (in field operations)
        // see https://kewth.github.io/2019/10/21/二次剩余/
        // This also gives great confidence about the correctness of pow implementation
        let q_minus_1 = "02a437a4b8c35fc74bd278eaa22f25e9e2dc90e50e7046b466e59e49349e8bd050a62cfd16ddca6ef53149330978ef011d68619c86185c7b292e85a87091a04966bf91ed3e71b743162c338362113cfd7ced6b1d76382eab26aa00001c718e38";
        let random = Fp2VarDef::constant(Fq2::new(MontFp!("9234798333332431749808964431269"), MontFp!("382952467575689436")));
        let power = mapper_cons.pow(&random, q_minus_1);
        assert_eq!(power.value().unwrap(), Fq2::one());
    }

    #[test]
    fn test_map_to_curve() {
        let test_vector = [
            Fq2::one(),
            Fq2::zero(),
            Fq2::new(MontFp!("0"), MontFp!("1")),
            Fq2::new(MontFp!("4668743795729856927659652"), MontFp!("32748932719472543265")),
        ];

        for point in test_vector {
            println!("point: {}", point);

            let mapper = WBMap::<ark_bls12_381::g2::Config>::new().unwrap();
            let point_curve = mapper.map_to_curve(point).unwrap();
            println!("curve: {}, {}", point_curve.x, point_curve.y);

            let cs = ConstraintSystem::<ConstraintF>::new_ref();
            let mapper_cons = CurveMapperWithCons::new(cs).unwrap();

            let point_var = Fp2VarDef::constant(point);
            let point_curve_var = mapper_cons.map_to_curve(point_var);

            assert_eq!(point_curve.x, point_curve_var.x.value().unwrap());
            assert_eq!(point_curve.y, point_curve_var.y.value().unwrap());
        }
    }

    #[test]
    fn test_clear_cofactor() {
        let g = G2::generator();
        let g_var = G2VarDef::constant(g);

        let g_cleared = g.into_affine().clear_cofactor();

        let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let domain_var:  Vec<UInt8<ConstraintF>> = UInt8::<ConstraintF>::constant_vec(domain);

        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let curve_hasher = MapToCurveHasherWithCons::new(cs, &domain_var).unwrap();

        let cleared_var = curve_hasher.clear_cofactor2(&g_var);
        assert_eq!(g_cleared, cleared_var.value().unwrap().into_affine());
    }

    #[test]
    fn test_hash_to_curve() {
        let test_vector = [
            "",
            "abc",
            "lightec",
            "Bitcoin Layer 2, Native",
            "Euler's Theorem states that if gcd(a,n) = 1, then a^φ(n) ≡ 1 (mod n). Here φ(n) is Euler's totient function: the number of integers in {1, 2, . . ., n-1} which are relatively prime to n. -- from https://t5k.org/glossary/page.php?sort=EulersTheorem",
        ];

        for msg in test_vector {
            let point = crate::bls::hash_to_g2(&msg.as_ref());

            let msg_var = UInt8::<ConstraintF>::constant_vec(&msg.as_ref());
            let cs = ConstraintSystem::<ConstraintF>::new_ref();
            let point_var = hash_to_g2_with_cons(cs, &msg_var);

            assert_eq!(point.into_affine(), point_var.value().unwrap().into_affine());
        }
    }
}
