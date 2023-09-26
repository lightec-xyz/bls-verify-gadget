
use core::marker::PhantomData;
use ark_ec::bls12::{Bls12, Bls12Config};
use ark_ec::pairing::Pairing;
use ark_r1cs_std::groups::bls12;
use ark_r1cs_std::prelude::PairingVar as PG;
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError, ConstraintSystemRef};
use ark_std::vec::Vec;
use ark_ec::hashing::curve_maps::wb::WBConfig;
use ark_crypto_primitives::signature::constraints::SigVerifyGadget;


use derivative::Derivative;

use core::borrow::Borrow;
use core::ops::Add;

use crate::bls::*;

type ConstraintF<P: Bls12Config> = P::Fp;
type PairingVar<P: Bls12Config> = ark_r1cs_std::pairing::bls12::PairingVar<P>;


pub struct ParametersVar<P: Bls12Config>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a, <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    pub g1_generator: bls12::G1Var<P>,
}

impl <P: Bls12Config> Clone for ParametersVar<P> {
    fn clone(&self) -> Self {
        ParametersVar {
            g1_generator: self.g1_generator,
        }
    }
}


#[derive(Derivative)]
pub struct PublicKeyVar<P: Bls12Config>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    pub public_key: bls12::G1Var<P>,
}

impl <P: Bls12Config> Clone for PublicKeyVar<P> {
    fn clone(&self) -> Self {
        PublicKeyVar {
            public_key: self.public_key,
        }
    }
}

#[derive(Derivative)]
pub struct SignatureVar<P: Bls12Config>
where
    for<'a> &'a bls12::G2Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G2, bls12::G2Var<P>>,
{
    pub sig: bls12::G2Var<P>,
}

impl <P: Bls12Config> Clone for SignatureVar<P> {
    fn clone(&self) -> Self {
        SignatureVar {
            sig: self.sig,
        }
    }
}


pub struct BlsSignatureVerifyGadget<P: Bls12Config>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
    for<'a> &'a bls12::G2Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G2, bls12::G2Var<P>>,
    P::G2Config: WBConfig,
{
    _v: PhantomData<P>,
}


impl <P: Bls12Config> SigVerifyGadget<BLS<P>, ConstraintF<P>> for BlsSignatureVerifyGadget<P>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
    for<'a> &'a bls12::G2Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G2, bls12::G2Var<P>>,
    P::G2Config: WBConfig,
{
    type ParametersVar = ParametersVar<P>;
    type PublicKeyVar = PublicKeyVar<P>;
    type SignatureVar = SignatureVar<P>;

    /// on-curve or prime order check is *not* performed for public key or signature, see code comments
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<P>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<P>>, SynthesisError> {
        // security: ensuring that public key is not identity
        public_key.public_key.enforce_not_equal(&bls12::G1Var::<P>::zero())?;

        // security: ensuring that public key and siggnature are on curve and in their prime order sub group.
        // unfortunately both are not implemented in the lib, which is fine
        // if public key / signature are from known places (such as blockchain data) -- FIXME later
        // public_key.public_key.enforce_prime_order();
        // signature.sig.enforce_prime_order();

        let g1 : bls12::G1Var<P> = parameters.g1_generator.clone();
        let g1_neg = g1.negate()?;

        // in a typical signature verification use case,
        // parameter is usually a constant, and public key / message / signature
        // could be constant, witness or variable
        // let's try our best to obtain the constrain system
        let cs = extract_cs(public_key, message, signature);
        let h: bls12::G2Var<P> = crate::hasher::hash_to_g2_with_cons::<P>(cs, message);

        let g1_neg_prepared  = PairingVar::<P>::prepare_g1(&g1_neg).unwrap();
        let h_prepared = PairingVar::<P>::prepare_g2(&h).unwrap();
        let public_key_prepared = PairingVar::<P>::prepare_g1(&public_key.public_key).unwrap();
        let signature_prepared  = PairingVar::<P>::prepare_g2(&signature.sig).unwrap();
        let paired = PairingVar::<P>::product_of_pairings(&[g1_neg_prepared, public_key_prepared], &[signature_prepared, h_prepared]).unwrap();

        paired.is_one()
    }

}

fn extract_cs<P: Bls12Config>(public_key: &PublicKeyVar<P>, message: &[UInt8<ConstraintF<P>>], signature: &SignatureVar<P>) -> ConstraintSystemRef<ConstraintF<P>> {
    let cs= match public_key.public_key.cs() {
        ConstraintSystemRef::None => {
            match message.cs() {
                ConstraintSystemRef::None => {
                    match signature.sig.cs() {
                        ConstraintSystemRef::None => panic!("Constraint system is none."),
                        ConstraintSystemRef::CS(_) => signature.sig.cs().clone()
                    }
                },
                ConstraintSystemRef::CS(_) => message.cs().clone()
            }
        },
        ConstraintSystemRef::CS(_) => public_key.public_key.cs().clone()
    };
    cs
}

impl <P: Bls12Config> BlsSignatureVerifyGadget<P>
where
    P::G2Config: WBConfig
{
    pub fn aggregate_verify(
        parameters: &ParametersVar<P>,
        public_keys: &[PublicKeyVar<P>],
        bitmap: &[Boolean<P::Fp>],
        message: &[UInt8<ConstraintF<P>>],
        signature: &SignatureVar<P>,
    ) -> Result<(Boolean<ConstraintF<P>>, UInt32<ConstraintF<P>>), SynthesisError> {
        assert_eq!(public_keys.len(), bitmap.len());

        let cs = extract_cs(&public_keys[0], message, signature);
        let (public_key, count) = Self::mapped_aggregate(cs.clone(), public_keys, bitmap).unwrap();

        let r = Self::verify(parameters, &public_key, message, signature).unwrap();
        Ok((r, count))
    }

    pub fn mapped_aggregate(
        cs: ConstraintSystemRef<ConstraintF<P>>,
        public_keys: &[PublicKeyVar<P>],
        bitmap: &[Boolean<ConstraintF<P>>],
    ) -> Result<(PublicKeyVar<P>, UInt32<ConstraintF<P>>), SynthesisError> {
        let zero = bls12::G1Var::<P>::zero();
        let mut ret = zero.clone();
        let count_zero = UInt32::<ConstraintF<P>>::constant(0u32);
        let count_one = UInt32::<ConstraintF<P>>::constant(1u32);
        let mut count = UInt32::<ConstraintF<P>>::new_variable(cs, || Ok(0), AllocationMode::Witness).unwrap();

        for (bit, key) in bitmap.iter().zip(public_keys.iter()) {
            ret = ret + bit.select(&key.public_key, &zero).unwrap();
            count = UInt32::<ConstraintF<P>>::addmany(&[count.clone(), bit.select(&count_one, &count_zero).unwrap()]).unwrap();
        }

        Ok((PublicKeyVar { public_key: ret}, count.clone()))
    }
}

impl <P: Bls12Config>  AllocVar<Parameters<P>, ConstraintF<P>> for ParametersVar<P>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    fn new_variable<T: Borrow<Parameters<P>>>(
        cs: impl Into<Namespace<ConstraintF<P>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = bls12::G1Var::<P>::new_variable(cs.clone(), || Ok(val.borrow().g1_generator), mode)?;
            Ok(Self {
                g1_generator: generator,
            })
        })
    }
}

impl <P: Bls12Config>  AllocVar<PublicKey<P>, ConstraintF<P>> for PublicKeyVar<P>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    fn new_variable<T: Borrow<PublicKey<P>>>(
        cs: impl Into<Namespace<ConstraintF<P>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let key_var = bls12::G1Var::<P>::new_variable(cs.clone(), || Ok(val.borrow().public_key), mode)?;
            Ok(Self {
                public_key: key_var,
            })
        })
    }
}

impl <P: Bls12Config> AllocVar<Signature<P>, ConstraintF<P>> for SignatureVar<P>
where
    for<'a> &'a bls12::G2Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G2, bls12::G2Var<P>>,
{
    fn new_variable<T: Borrow<Signature<P>>>(
        cs: impl Into<Namespace<ConstraintF<P>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let sig = bls12::G2Var::<P>::new_variable(cs.clone(), || Ok(val.borrow().sig), mode)?;
            Ok(Self {
                sig,
            })
        })
    }
}

impl <P: Bls12Config> EqGadget<ConstraintF<P>> for PublicKeyVar<P>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<P>>, SynthesisError> {
        self.public_key.is_eq(&other.public_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<P>>,
    ) -> Result<(), SynthesisError> {
        self.public_key
            .conditional_enforce_equal(&other.public_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<P>>,
    ) -> Result<(), SynthesisError> {
        self.public_key
            .conditional_enforce_not_equal(&other.public_key, condition)
    }
}

impl <P: Bls12Config> ToBytesGadget<ConstraintF<P>> for PublicKeyVar<P>
where
    for<'a> &'a bls12::G1Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G1, bls12::G1Var<P>>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<P>>>, SynthesisError> {
        self.public_key.to_bytes()
    }
}

impl <P: Bls12Config> ToBytesGadget<ConstraintF<P>> for SignatureVar<P>
where
    for<'a> &'a bls12::G2Var<P>: GroupOpsBounds<'a,  <Bls12<P> as Pairing>::G2, bls12::G2Var<P>>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<P>>>, SynthesisError> {
        self.sig.to_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::zip;


    // use crate::{constraints::{ParametersVar, PublicKeyVar, SignatureVar, F}, bls::{Parameters, PublicKey, Signature}};
    use ark_r1cs_std::{prelude::{AllocationMode, Boolean}, uint8::UInt8};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use hex::*;
    use crate::bls::*;
    use ark_crypto_primitives::signature::SigVerifyGadget;

    type Config = ark_bls12_381::Config;
    type Fq = ark_bls12_381::Fq;

    #[test]
    fn test_verify() {
        // use case from ../tests/test_cases/verify
        // "pubkey": "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        // "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
        // "signature": "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"},
        // "output": true}

        let msgs = [
            "5656565656565656565656565656565656565656565656565656565656565656", // valid
            "5656565656565656565656565656565656565656565656565656565656565657", // invalid
            "7878787878787878787878787878787878787878787878787878787878787878" // invalid
        ];

        let expects = [true, false, false];

        for (msg, expect) in zip(msgs, expects) {

            let cs = ConstraintSystem::<Fq>::new_ref();

            let public_key = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
            let public_key = PublicKey::<Config>::try_from(public_key).unwrap();

            let msg = <[u8; 32]>::from_hex(msg).unwrap();
            let msg = <UInt8<Fq>>::new_witness_vec(cs.clone(), &msg);

            let sig = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb";
            let sig = Signature::try_from(sig).unwrap();

            let result: Boolean<Fq> = BlsSignatureVerifyGadget::verify(
                &ParametersVar::new_variable(cs.clone(), || Ok(Parameters::default()), AllocationMode::Constant).unwrap(),
                &PublicKeyVar::new_variable(cs.clone(), || Ok(public_key), AllocationMode::Witness).unwrap(),
                msg.as_ref().unwrap(),
                &SignatureVar::new_variable(cs.clone(), || Ok(sig), AllocationMode::Witness).unwrap()
            ).unwrap();

            println!("verification result: {} constraint size: {}", result.value().unwrap(), cs.num_constraints());
            assert_eq!(result.value().unwrap(), expect);
        }
    }

    #[test]
    fn test_aggregate_verify() {
        // use case from ../tests/test_cases/fast_aggregate_verify
        // {"input":
        // {"pubkeys": ["0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        // "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"],
        // "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
        // "signature": "0x912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1"},
        // "output": true}

        let cs = ConstraintSystem::<Fq>::new_ref();

        let pub_key1 = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
        let pub_key2 = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81";
        let pub_key1 = PublicKey::<Config>::try_from(pub_key1).unwrap();
        let pub_key2 = PublicKey::<Config>::try_from(pub_key2).unwrap();
        let mut pub_keys = Vec::with_capacity(512);
        pub_keys.push(PublicKeyVar::new_variable(cs.clone(), || Ok(pub_key1), AllocationMode::Witness).unwrap());
        for i in 1..512 {
            pub_keys.push(PublicKeyVar::new_variable(cs.clone(), || Ok(pub_key2.clone()), AllocationMode::Witness).unwrap());
        }

        let mut bitmap = Vec::with_capacity(512);
        bitmap.push(Boolean::<Fq>::new_witness(cs.clone(), || Ok(true)).unwrap());
        bitmap.push(Boolean::<Fq>::new_witness(cs.clone(), || Ok(true)).unwrap());
        for i in 2..512 {
            bitmap.push(Boolean::<Fq>::new_witness(cs.clone(), || Ok(false)).unwrap());
        }

        let msg = "5656565656565656565656565656565656565656565656565656565656565656";
        let msg = <[u8; 32]>::from_hex(msg).unwrap();
        let msg = <UInt8<Fq>>::new_witness_vec(cs.clone(), &msg);

        let sig = "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1";
        let sig = Signature::try_from(sig).unwrap();

        let (result, count) = BlsSignatureVerifyGadget::aggregate_verify(
            &ParametersVar::new_variable(cs.clone(), || Ok(Parameters::default()), AllocationMode::Constant).unwrap(),
            &pub_keys.as_ref(),
            &bitmap.as_ref(),
            msg.as_ref().unwrap(),
            &SignatureVar::new_variable(cs.clone(), || Ok(sig), AllocationMode::Witness).unwrap()
        ).unwrap();

        println!("verification result: {} constraint size: {} effective public key count: {}",
            result.value().unwrap(), cs.num_constraints(), count.value().unwrap());
        assert_eq!(result.value().unwrap(), true);
    }
    #[test]
    fn test_aggregate_verify_neg() {
        // use case from ../tests/test_cases/fast_aggregate_verify
        // {"input":
        // {"pubkeys": ["0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        // "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"],
        // "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
        // "signature": "0x912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1"},
        // "output": true}

        let cs = ConstraintSystem::<Fq>::new_ref();

        let pub_key1 = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
        let pub_key2 = "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81";
        let pub_key1 = PublicKey::<Config>::try_from(pub_key1).unwrap();
        let pub_key2 = PublicKey::<Config>::try_from(pub_key2).unwrap();
        let mut pub_keys = Vec::with_capacity(512);
        pub_keys.push(PublicKeyVar::new_variable(cs.clone(), || Ok(pub_key1), AllocationMode::Witness).unwrap());
        for i in 1..512 {
            pub_keys.push(PublicKeyVar::new_variable(cs.clone(), || Ok(pub_key2.clone()), AllocationMode::Witness).unwrap());
        }

        let mut bitmap = Vec::with_capacity(512);
        for i in 0..512 {
            bitmap.push(Boolean::<Fq>::new_witness(cs.clone(), || Ok(true)).unwrap());
        }

        let msg = "5656565656565656565656565656565656565656565656565656565656565656";
        let msg = <[u8; 32]>::from_hex(msg).unwrap();
        let msg = <UInt8<Fq>>::new_witness_vec(cs.clone(), &msg);

        let sig = "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1";
        let sig = Signature::try_from(sig).unwrap();

        let (result, count) = BlsSignatureVerifyGadget::aggregate_verify(
            &ParametersVar::new_variable(cs.clone(), || Ok(Parameters::default()), AllocationMode::Constant).unwrap(),
            &pub_keys.as_ref(),
            &bitmap.as_ref(),
            msg.as_ref().unwrap(),
            &SignatureVar::new_variable(cs.clone(), || Ok(sig), AllocationMode::Witness).unwrap()
        ).unwrap();

        println!("verification result: {} constraint size: {} effective public key count: {}",
            result.value().unwrap(), cs.num_constraints(), count.value().unwrap());
        assert_eq!(result.value().unwrap(), false);
    }
}
