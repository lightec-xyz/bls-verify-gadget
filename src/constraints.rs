use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_r1cs_std::fields::fp12::Fp12Var;
use ark_r1cs_std::groups::bls12;
use ark_r1cs_std::prelude::PairingVar as PG;
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError, ConstraintSystemRef};
use ark_std::vec::Vec;

use ark_crypto_primitives::signature::constraints::SigVerifyGadget;

use derivative::Derivative;

use core::borrow::Borrow;

use crate::bls::*;

type Config = ark_bls12_381::Config;
type C1 = <Bls12<Config> as Pairing>::G1;
type C2 = <Bls12<Config> as Pairing>::G2;
type CV1 = bls12::G1Var<Config>;
type CV2 = bls12::G2Var<Config>;
type F = ark_bls12_381::Fq;
type PairingVar = ark_r1cs_std::pairing::bls12::PairingVar<Config>;
type GTVar = Fp12Var<ark_bls12_381::Fq12Config>;

#[derive(Clone)]
pub struct ParametersVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    pub g1_generator: CV1,
}

#[derive(Derivative, Clone)]
pub struct PublicKeyVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    pub pub_key: CV1,
}

#[derive(Derivative, Clone)]
pub struct SignatureVar
where
    for<'a> &'a CV2: GroupOpsBounds<'a, C2, CV2>,
{
    pub sig: CV2,
}

pub struct BlsSignatureVerifyGadget
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
    for<'a> &'a CV2: GroupOpsBounds<'a, C2, CV2>,
{
}

impl SigVerifyGadget<BLS, F>
for BlsSignatureVerifyGadget
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
    for<'a> &'a CV2: GroupOpsBounds<'a, C2, CV2>,
{
    type ParametersVar = ParametersVar;
    type PublicKeyVar = PublicKeyVar;
    type SignatureVar = SignatureVar;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<F>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        // let g1 : G1Affine = parameters.g1_generator.clone().into();
        // let g1_neg = G1Projective::from(g1.neg());
        let g1 : CV1 = parameters.g1_generator.clone();
        let g1_neg = g1.negate()?;

        // in a typical signature verification use case,
        // parameter is usually a constant, and public key / message / signature
        // could be constant, witness or variable
        // let's try our best to obtain the constrain system
        let cs: ConstraintSystemRef<F> = match public_key.pub_key.cs() {
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
            ConstraintSystemRef::CS(_) => public_key.pub_key.cs().clone()
        };
        let h = crate::hasher::hash_to_g2_with_cons(cs, message);

        let g1_neg_prepared = PairingVar::prepare_g1(&g1_neg).unwrap();
        let h_prepared = PairingVar::prepare_g2(&h).unwrap();
        let public_key_prepared = PairingVar::prepare_g1(&public_key.pub_key).unwrap();
        let signature_prepared = PairingVar::prepare_g2(&signature.sig).unwrap();
        let paired: GTVar = PairingVar::product_of_pairings(&[g1_neg_prepared, public_key_prepared], &[signature_prepared, h_prepared]).unwrap();

        paired.is_one()
    }
}


impl AllocVar<Parameters, F> for ParametersVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = CV1::new_variable(cs.clone(), || Ok(val.borrow().g1_generator), mode)?;
            Ok(Self {
                g1_generator: generator,
            })
        })
    }
}

impl AllocVar<PublicKey, F> for PublicKeyVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let key_var = CV1::new_variable(cs.clone(), || Ok(val.borrow().pub_key), mode)?;
            Ok(Self {
                pub_key: key_var,
            })
        })
    }
}

impl AllocVar<Signature, F> for SignatureVar
where
    for<'a> &'a CV2: GroupOpsBounds<'a, C2, CV2>,
{
    fn new_variable<T: Borrow<Signature>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let sig = CV2::new_variable(cs.clone(), || Ok(val.borrow().sig), mode)?;
            Ok(Self {
                sig,
            })
        })
    }
}

impl EqGadget<F> for PublicKeyVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl ToBytesGadget<F> for PublicKeyVar
where
    for<'a> &'a CV1: GroupOpsBounds<'a, C1, CV1>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}

impl ToBytesGadget<F> for SignatureVar
where
    for<'a> &'a CV2: GroupOpsBounds<'a, C2, CV2>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.sig.to_bytes()
    }
}

#[cfg(test)]
mod test {

    use std::iter::zip;

    use crate::{constraints::{ParametersVar, PublicKeyVar, SignatureVar, F}, bls::{Parameters, PublicKey, Signature}};
    use ark_r1cs_std::{prelude::{AllocationMode, Boolean}, uint8::UInt8};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use hex::*;

    use super::BlsSignatureVerifyGadget;
    use ark_crypto_primitives::signature::SigVerifyGadget;

    #[test]
    fn test_verify() {
        // use case from ../tests/test_cases/verify
        // "pubkey": "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        // "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
        // "signature": "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"},
        // "output": true}

        let msgs = [
            "5656565656565656565656565656565656565656565656565656565656565656", // valid
            "7878787878787878787878787878787878787878787878787878787878787878" // invalid
        ];

        let expects = [true, false];

        for (msg, expect) in zip(msgs, expects) {

            let cs = ConstraintSystem::<F>::new_ref();

            let pub_key = "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
            let pub_key = PublicKey::try_from(pub_key).unwrap();

            let msg = <[u8; 32]>::from_hex(msg).unwrap();
            let msg = <UInt8<F>>::new_witness_vec(cs.clone(), &msg);

            let sig = "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb";
            let sig = Signature::try_from(sig).unwrap();

            let result: Boolean<F> = BlsSignatureVerifyGadget::verify(
                &ParametersVar::new_variable(cs.clone(), || Ok(Parameters::default()), AllocationMode::Constant).unwrap(),
                &PublicKeyVar::new_variable(cs.clone(), || Ok(pub_key), AllocationMode::Witness).unwrap(),
                msg.as_ref().unwrap(),
                &SignatureVar::new_variable(cs.clone(), || Ok(sig), AllocationMode::Witness).unwrap()
            ).unwrap();

            println!("verification result: {}\nconstraint size: {}", result.value().unwrap(), cs.num_constraints());
            assert_eq!(result.value().unwrap(), expect);
        }
    }
}