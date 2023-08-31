use ark_ec::{CurveGroup, CurveConfig, hashing::HashToCurveError, bls12::{Bls12, Bls12Config}, pairing::Pairing};
use ark_ff::{Field, PrimeField, BitIteratorBE};
use ark_r1cs_std::{
    uint8::UInt8,
    prelude::{CurveVar, AllocVar},
    boolean,
    groups::bls12::G2Var,
    fields::{fp2::Fp2Var, fp::FpVar, FieldVar},
    R1CSVar,
    ToConstraintFieldGadget,
    ToBytesGadget,
};

use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_relations::r1cs::ConstraintSystemRef;

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

        let z_pad = UInt8::constant_vec(&[0u8; 64]);

        let lib_str: [u8; 2] = (len_in_bytes as u16).to_be_bytes();
        let lib_str_var = UInt8::<ConstraintF>::new_witness_vec(self.cs.clone(), &lib_str).unwrap();

        let mut msg_prime = z_pad.clone();
        msg_prime.extend_from_slice(message);
        msg_prime.extend_from_slice(&lib_str_var);
        msg_prime.push(UInt8::constant(0u8));
        msg_prime.extend_from_slice(&dst_prime);
        let b0 :Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&msg_prime).unwrap().to_bytes().unwrap();

        let mut data = b0.clone();
        data.push(UInt8::constant(1u8));
        data.extend_from_slice(&dst_prime);
        let b1 :Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&data).unwrap().to_bytes().unwrap();

        let mut ret = b1.clone();
        let mut last_b = b1.clone();
        for i in 2..ell {
            let mut bx = std::iter::zip(b0.iter(), last_b.iter())
                .into_iter()
                .map(|(a, b)| a.xor(b).unwrap())
                .collect::<Vec<UInt8<ConstraintF>>>();
            bx.push(UInt8::new_witness(self.cs.clone(), || Ok(i as u8)).unwrap());
            bx.extend_from_slice(&dst_prime);
            let bi :Vec<UInt8<ConstraintF>> = Sha256Gadget::<ConstraintF>::digest(&bx).unwrap().to_bytes().unwrap();
            ret.extend_from_slice(&bi);

            last_b = bx.clone();
        }

        assert!(ret.len() == len_in_bytes);

        ret
    }

}

pub struct CurveMapperWithCons{
    cs: ConstraintSystemRef<ConstraintF>,
}

impl CurveMapperWithCons
{
    fn new(cs: ConstraintSystemRef<ConstraintF>) -> Result<Self, HashToCurveError> {
        Ok(CurveMapperWithCons{
            cs: cs.clone(),
        })
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
    fn new(cs: ConstraintSystemRef<ConstraintF>, domain: &[UInt8<ConstraintF>]) -> Result<Self, HashToCurveError> {
        let field_hasher = DefaultFieldHasherWithCons::new(cs.clone(), domain);
        let curve_mapper = CurveMapperWithCons::new(cs.clone())?;
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

pub fn hash_to_g2_with_cons(cs: ConstraintSystemRef<ConstraintF>, message: &[UInt8<ConstraintF>]) -> G2VarDef {
        
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let domain_var : Vec<UInt8<ConstraintF>> = domain.iter()
        .map(|t| UInt8::<ConstraintF>::constant(*t))
        .collect::<Vec<UInt8<ConstraintF>>>();

    let curve_hasher = MapToCurveHasherWithCons
    ::new(cs, &domain_var)
    .unwrap();

    curve_hasher.hash(message).unwrap()
}
