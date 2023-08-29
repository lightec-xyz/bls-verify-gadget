use ark_ec::{CurveGroup, CurveConfig, hashing::HashToCurveError, bls12::{Bls12, Bls12Config}, pairing::Pairing};
use ark_ff::{Field, PrimeField, BitIteratorBE};
use ark_r1cs_std::{
    uint8::UInt8,
    prelude::CurveVar,
    boolean,
    groups::bls12::G2Var,
    fields::{fp2::Fp2Var, fp::FpVar, FieldVar},
    ToConstraintFieldGadget,
};

use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;

const MAX_DST_LENGTH: usize = 255;

/// quick and dirty hack from existing arkworks codes in algebra/ff and algebra/ec
/// for BLS over BLS12-381 only, as specified in ETH2, *not* intended for generic uses

type G2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2;
type BaseField = <G2 as CurveGroup>::BaseField;
type ConstraintF = <BaseField as Field>::BasePrimeField;
type FpVarDef = FpVar<<ark_bls12_381::Config as Bls12Config>::Fp>;
type Fp2VarDef = Fp2Var<<ark_bls12_381::Config as Bls12Config>::Fp2Config>;
type G2VarDef = G2Var<ark_bls12_381::Config>;
pub struct DefaultFieldHasherWithCons<const SEC_PARAM: usize = 128> {
    len_per_base_elem: usize,
    sha256: Sha256Gadget<ConstraintF>,
    dst: Vec<UInt8<ConstraintF>>,
}

impl<const SEC_PARAM: usize> DefaultFieldHasherWithCons<SEC_PARAM>
{
    fn new(dst: &[UInt8<ConstraintF>]) -> Self {
        assert!(dst.len() <= MAX_DST_LENGTH);
        
        // The final output of `hash_to_field` will be an array of field
        // elements from TargetField, each of size `len_per_elem`.
        let len_per_base_elem = Self::get_len_per_elem::<BaseField>();

        let sha256 = Sha256Gadget::default();

        DefaultFieldHasherWithCons {
            len_per_base_elem,
            sha256,
            dst: dst.to_vec(),
        }
    }

    fn hash_to_field(&self, message: &[UInt8<ConstraintF>], count: usize) -> Vec<Fp2VarDef> {
        let m = BaseField::extension_degree() as usize;
        assert!(m == 2);

        // The user imposes a `count` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes: usize = count * m * self.len_per_base_elem;
        let uniform_bytes = Self::expand(message, len_in_bytes);

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
                let f_head : Vec<FpVarDef> = head.to_constraint_field().unwrap();
                let f_tail : Vec<FpVarDef> = tail.to_constraint_field().unwrap();

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

    fn expand(message: &[UInt8<ConstraintF>], len_in_bytes: usize) -> Vec<UInt8<ConstraintF>> {
        todo!();
    }

    /// This function computes the length in bytes that a hash function should output
    /// for hashing an element of type `Field`.
    /// See section 5.1 and 5.3 of the
    /// [IETF hash standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
    fn get_len_per_elem<F: Field>() -> usize {
        // ceil(log(p))
        let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
        // ceil(log(p)) + security_parameter
        let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
        // ceil( (ceil(log(p)) + security_parameter) / 8)
        let bytes_per_base_field_elem =
            ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
        bytes_per_base_field_elem as usize
    }

}

pub struct CurveMapperWithCons{}

impl CurveMapperWithCons
{
    fn new() -> Result<Self, HashToCurveError> {
        Ok(CurveMapperWithCons{})
    }

    fn map_to_curve(&self, point: Fp2VarDef) -> Result<G2VarDef, HashToCurveError> {
        todo!()
    }
}

pub struct MapToCurveHasherWithCons
{
    field_hasher: DefaultFieldHasherWithCons,
    curve_mapper: CurveMapperWithCons,
}

impl MapToCurveHasherWithCons
{
    fn new(domain: &[UInt8<ConstraintF>]) -> Result<Self, HashToCurveError> {
        let field_hasher = DefaultFieldHasherWithCons::new(domain);
        let curve_mapper = CurveMapperWithCons::new()?;
        Ok(MapToCurveHasherWithCons {
            field_hasher,
            curve_mapper,
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

        let rand_curve_elem_0 = self.curve_mapper.map_to_curve(rand_field_elems[0].clone())?;
        let rand_curve_elem_1 = self.curve_mapper.map_to_curve(rand_field_elems[1].clone())?;

        let rand_curve_elem: G2VarDef = (rand_curve_elem_0 + rand_curve_elem_1).into();

        // FIXME: LE or BE?
        let mut cofactor_bits = BitIteratorBE::new(ark_bls12_381::g2::Config::COFACTOR)
            .map(boolean::Boolean::constant)
            .collect::<Vec<boolean::Boolean<ConstraintF>>>();
        cofactor_bits.reverse();

        let rand_subgroup_elem = rand_curve_elem.scalar_mul_le(cofactor_bits.iter()).unwrap();
        Ok(rand_subgroup_elem.into())
    }
}

pub fn hash_to_g2_with_cons(message: &[UInt8<ConstraintF>]) -> G2VarDef {
        
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let domain_var : Vec<UInt8<ConstraintF>> = domain.iter()
        .map(|t| UInt8::<ConstraintF>::constant(*t))
        .collect::<Vec<UInt8<ConstraintF>>>();

    let curve_hasher = MapToCurveHasherWithCons
    ::new(&domain_var)
    .unwrap();

    curve_hasher.hash(message).unwrap()
}
