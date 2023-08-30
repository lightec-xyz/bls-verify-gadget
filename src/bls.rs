use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::{Error, CryptoError};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, G1Affine, Fq2};

use ark_ff::{BigInt};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
use ark_ec::bls12::Bls12;
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher, curve_maps::wb::WBMap};
use ark_ff::field_hashers::DefaultFieldHasher;

use ark_std::{rand::Rng, ops::Mul, ops::Neg, UniformRand, One};

use std::borrow::Borrow;
use sha2::Sha256;
use hex::{self, FromHex};

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


//input MUST be in little-endian hex string
impl TryFrom<String> for PrivateKey {
    type Error = SerializationError;
    fn try_from(s: String) -> Result<PrivateKey, SerializationError> {  
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string 
impl TryFrom<&str> for PrivateKey {
    type Error = SerializationError;
    fn try_from(s: &str) -> Result<PrivateKey, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian 
impl TryFrom<&[u8]> for PrivateKey {
    type Error = SerializationError;
    fn try_from(bytes: &[u8]) -> Result<PrivateKey, SerializationError> {
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}


//output is in little-endian
impl Into<String> for PrivateKey{
    fn into(self) -> String {
        let mut serialized = vec![0; 32];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
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

impl PublicKey{
    pub fn aggregate(public_keys: &Vec<PublicKey>) -> Option<PublicKey> {
        if public_keys.len() == 0{
            None
        }else{
            Some(
                public_keys.into_iter()
                .map(|p| p.borrow().0)
                .sum::<G1Projective>()
                .into())
        }
    }
}

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

//input MUST be in little-endian 
impl TryFrom<&[u8]> for PublicKey{
    type Error = SerializationError;
    fn try_from(bytes : &[u8]) -> Result<PublicKey, SerializationError> {
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl TryFrom<String> for PublicKey {
    type Error = SerializationError;
    fn try_from(s:String) -> Result<PublicKey, SerializationError> {
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl TryFrom<&str> for PublicKey {
    type Error = SerializationError;
    fn try_from(s:&str) -> Result<PublicKey, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//output is in little-endian
impl Into<String> for PublicKey{
    fn into(self) -> String {
        let mut serialized = vec![0; 48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
impl Into<Vec<u8>> for PublicKey{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0;48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
    }
}

#[derive(Default)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature(G2Projective);

impl Signature {
    pub fn aggregate(signatures: &Vec<Signature>) -> Option<Signature> {
        if signatures.len() == 0{
            None
        }else{
            Some(
                signatures.into_iter()
                .map(|s| s.borrow().0)
                .sum::<G2Projective>()
                .into()
            )
        }
    }
}

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

//input MUST be in little-endian 
impl TryFrom<&[u8]> for Signature{
    type Error = SerializationError;
    fn try_from(bytes : &[u8]) -> Result<Signature, SerializationError> {
        Signature::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl TryFrom<String> for Signature {
    type Error = SerializationError;
    fn try_from(s:String) ->  Result<Signature, SerializationError>  {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string 
impl TryFrom<&str> for Signature {
    type Error = SerializationError;
    fn try_from(s:&str) -> Result<Signature, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..])
    }
}

//output is in little-endian
impl Into<String> for Signature{
    fn into(self) -> String {
        let mut serialized = vec![0; 96];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
impl Into<Vec<u8>> for Signature{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0;96];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
    }
}

#[derive(Debug)]
pub enum BLSError {
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
}


impl core::fmt::Display for BLSError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InvalidSecretKey => format!("invalid secret key"),
            Self::InvalidPublicKey => "invalid public key".to_owned(),
            Self::InvalidSignature => "invalid signature".to_owned(),
        };
        write!(f, "{}", msg)
    }
}

impl ark_std::error::Error for BLSError {}


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
        if *sk == Self::SecretKey::default() {
            return Err(Box::new(BLSError::InvalidSecretKey))
        }
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
        if *pk == Self::PublicKey::default() {
            return Err(Box::new(BLSError::InvalidPublicKey))
        }
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
