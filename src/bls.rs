use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, G1Affine, G2Affine};

use ark_ff::{BigInt};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{Group, CurveGroup};
use ark_ec::bls12::Bls12;
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher, curve_maps::wb::WBMap};
use ark_ff::field_hashers::DefaultFieldHasher;
use num_bigint;

use ark_std::{rand::Rng, ops::Mul, ops::Neg, UniformRand, One};


use std::borrow::Borrow;
use std::str::from_boxed_utf8_unchecked;
use sha2::Sha256;
use hex;

pub use ark_ec::pairing::*;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters {
    pub g1_generator : G1Projective,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            g1_generator : G1Projective::generator(),
        }
    }
}

#[derive(Default)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey(Fr);

impl From<Fr> for PrivateKey {
    fn from(sk: Fr) -> PrivateKey {
        PrivateKey(sk)
    }
}

//
impl From<String> for PrivateKey {
    fn from(s: String) -> PrivateKey {  
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..]).unwrap()    
    }
}

impl From<&str> for PrivateKey {
    fn from(s: &str) -> PrivateKey {
        let bytes = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..]).unwrap()    
    }
}

impl From<&[u8]> for PrivateKey {
    fn from(bytes: &[u8]) -> PrivateKey {
        PrivateKey::deserialize_compressed(&bytes[..]).unwrap()  
    }
}

//[u64;4] must be MontBackend representation
impl From<[u64;4]> for PrivateKey {
    fn from(sk:[u64;4]) -> PrivateKey {
        let val = BigInt(sk);
        PrivateKey(Fr::from(val))
    }
}


impl Into<String> for PrivateKey{
    fn into(self) -> String {
        let mut serialized = vec![0; 32];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

impl Into<Vec<u8>> for PrivateKey{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0; 32];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
    }
}

impl AsRef<Fr> for PrivateKey {
    fn as_ref(&self) -> &Fr {
        &self.0
    }
}

#[derive(Default)]
#[derive(Clone, Copy, Eq, Debug, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
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

impl From<String> for PublicKey {
    fn from(s:String) -> PublicKey {
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..]).unwrap()    
    }
}

impl From<&str> for PublicKey {
    fn from(s:&str) -> PublicKey {
        let bytes = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..]).unwrap()    
    }
}


impl Into<String> for PublicKey{
    fn into(self) -> String {
        let mut serialized = vec![0; 48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

impl Into<Vec<u8>> for PublicKey{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0;48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
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

impl From<String> for Signature {
    fn from(s:String) -> Signature {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..]).unwrap()    
    }
}

impl From<&str> for Signature {
    fn from(s:&str) -> Signature {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..]).unwrap()    
    }
}


impl Into<String> for Signature{
    fn into(self) -> String {
        let mut serialized = vec![0; 96];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

impl Into<Vec<u8>> for Signature{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0;96];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
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
        println!("sign after hash_to_g2 {:?}", h);
        let signature = Self::Signature::from(h.mul(sk.as_ref()));

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, Error> {
        let g1 : G1Affine = parameters.g1_generator.clone().into();
        let g1_neg = G1Projective::from(g1.neg());

        let h = hash_to_g2(message);
        
        let bls_paired : PairingOutput<Bls12_381> = Bls12::multi_pairing([g1_neg, *pk.as_ref()], [*signature.as_ref(), h]);

        Ok(bls_paired.0.is_one())
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

pub fn hash_to_g2(message: &[u8]) -> G2Projective {
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let curve_hasher = MapToCurveBasedHasher::<
        ark_ec::short_weierstrass::Projective<ark_bls12_381::g2::Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g2::Config>,
    >
    ::new(domain)
    .unwrap();

    G2Projective::from(curve_hasher.hash(message).unwrap())
}
