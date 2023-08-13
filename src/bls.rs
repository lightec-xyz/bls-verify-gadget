use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, G2Affine};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
use ark_ec::bls12::Bls12;
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher, curve_maps::wb::WBMap};
use ark_ff::field_hashers::DefaultFieldHasher;

use ark_std::{rand::Rng, ops::Mul, UniformRand};

use std::borrow::Borrow;
use sha2::Sha256;

pub use ark_ec::pairing::*;

#[derive(Default)]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters {
    pub g1_generator : G1Projective,
}

#[derive(Default)]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey(Fr);

impl From<Fr> for PrivateKey {
    fn from(sk: Fr) -> PrivateKey {
        PrivateKey(sk)
    }
}

impl AsRef<Fr> for PrivateKey {
    fn as_ref(&self) -> &Fr {
        &self.0
    }
}

#[derive(Default)]
#[derive(Clone, Eq, Debug, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey(G1Projective);

impl From<G1Projective> for PublicKey {
    fn from(pk: G1Projective) -> PublicKey {
        PublicKey(pk)
    }
}

impl AsRef<G1Projective> for PublicKey {
    fn as_ref(&self) -> &G1Projective {
        &self.0
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(sk: &PrivateKey) -> PublicKey {
        let generator = &<Bls12::<ark_bls12_381::Config> as Pairing>::G1::generator();
        PublicKey::from(generator.mul(sk.as_ref()))
    }
}

impl PublicKey {
    pub fn aggregate<P: Borrow<PublicKey>>(public_keys: impl IntoIterator<Item = P>) -> PublicKey {
        public_keys.into_iter()
            .map(|p| p.borrow().0)
            .sum::<G1Projective>()
            .into()
    }
}

#[derive(Default)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature(G2Projective);

impl From<G2Projective> for Signature {
    fn from(sig: G2Projective) -> Signature {
        Signature(sig)
    }
}

impl AsRef<G2Projective> for Signature {
    fn as_ref(&self) -> &G2Projective {
        &self.0
    }
}

impl Signature {
    pub fn aggregate<S: Borrow<Signature>>(signatures: impl IntoIterator<Item = S>) -> Signature {
        signatures.into_iter()
            .map(|s| s.borrow().0)
            .sum::<G2Projective>()
            .into()
    }
}

pub struct BLS ();

impl SignatureScheme for BLS {
    type Parameters = Parameters;
    type SecretKey = PrivateKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Parameters {
            g1_generator: <Bls12::<ark_bls12_381::Config> as Pairing>::G1::generator()
        })
    }

    fn keygen<R: Rng>(
        _parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        let private_key = Self::SecretKey::from(Fr::rand(rng));
        let public_key = Self::PublicKey::from(&private_key);

        Ok((
            public_key,
            private_key,
        ))
    }

    fn sign<R: Rng>(
        _parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        _rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let h : G2Projective = G2Projective::from(hash_to_g2(message));
        let signature = Self::Signature::from(h.mul(sk.as_ref()));

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, Error> {
        let g1 : &G1Projective = &parameters.g1_generator;
        let g1_affine : <Bls12<ark_bls12_381::Config> as Pairing>::G1Affine = (*g1).into();

        let pk_affine : <Bls12<ark_bls12_381::Config> as Pairing>::G1Affine = (*pk.as_ref()).into();

        let h_affine : G2Affine = hash_to_g2(message);
        
        let sig_affine : <Bls12<ark_bls12_381::Config> as Pairing>::G2Affine = (*signature.as_ref()).into();

        //TODO optimizations
        let e1 : PairingOutput<Bls12_381> = Bls12::pairing(g1_affine, sig_affine);
        let e2 : PairingOutput<Bls12_381> = Bls12::pairing(pk_affine, h_affine);

        Ok(e1.eq(&e2))
    }

    fn randomize_public_key(
        _pp: &Self::Parameters,
        _public_key: &Self::PublicKey,
        _randomness: &[u8],
    ) -> Result<Self::PublicKey, Error> {
        unimplemented!()
    }

    fn randomize_signature(
        _pp: &Self::Parameters,
        _signature: &Self::Signature,
        _randomness: &[u8],
    ) -> Result<Self::Signature, Error> {
        unimplemented!()
    }
}

pub fn hash_to_g2(message: &[u8]) -> G2Affine {
    let curve_hasher = MapToCurveBasedHasher::<
        ark_ec::short_weierstrass::Projective<ark_bls12_381::g2::Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g2::Config>,
    >
    ::new(&[1])
    .unwrap();

    curve_hasher.hash(message).unwrap()
}