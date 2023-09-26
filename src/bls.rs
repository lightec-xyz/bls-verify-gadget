use core::marker::PhantomData;

use std::fmt;
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::bls12::{Bls12, Bls12Config, G1Affine, G1Projective, G2Projective};
use ark_ec::hashing::curve_maps::wb::WBConfig;
use ark_ec::{Group, CurveConfig};
use ark_ec::hashing::{HashToCurve, map_to_curve_hasher::MapToCurveBasedHasher, curve_maps::wb::WBMap};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Valid};
use ark_ff::PrimeField;
use ark_ff::field_hashers::DefaultFieldHasher;
use std::hash::Hasher;
use ark_std::{rand::Rng, ops::Mul, ops::Neg, UniformRand, One};

use std::borrow::Borrow;
use sha2::Sha256;
use hex;

pub use ark_ec::pairing::*;

#[derive(Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters <P: Bls12Config> {
    pub g1_generator : G1Projective<P>,
}

impl <P: Bls12Config> Default for Parameters<P> {
    fn default() -> Self {
        Parameters {
            g1_generator: G1Projective::<P>::generator(),
        }
    }
}

impl <P: Bls12Config> Clone for Parameters<P> {
    fn clone(&self) -> Self {
        Parameters {
            g1_generator: self.g1_generator,
        }
    }
}

impl <P: Bls12Config> fmt::Debug for Parameters<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.g1_generator)
    }
}



#[derive(Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
 pub struct PrivateKey<P: Bls12Config>{
    pub private_key:  <<P as Bls12Config>::G1Config as CurveConfig>::ScalarField,
 }

 impl <P: Bls12Config> Default for PrivateKey<P> {
    fn default() -> Self {
        PrivateKey {
            private_key: PrimeField::from_be_bytes_mod_order (vec![].as_slice()),
        }
    }
}

 impl <P: Bls12Config> Clone for PrivateKey<P> {
    fn clone(&self) -> Self {
        PrivateKey {
            private_key: self.private_key,
        }
    }
}

impl <P: Bls12Config> fmt::Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.private_key)
    }
}

//input MUST be in little-endian hex string
impl<P: Bls12Config> TryFrom<String> for PrivateKey<P> {
    type Error = SerializationError;
    fn try_from(s: String) -> Result<Self, SerializationError> {  
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string 
impl<P: Bls12Config> TryFrom<&str> for PrivateKey<P> {
    type Error = SerializationError;
    fn try_from(s: &str) -> Result<Self, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian 
impl<P: Bls12Config> TryFrom<&[u8]> for PrivateKey<P> {
    type Error = SerializationError;
    fn try_from(bytes: &[u8]) -> Result<Self, SerializationError> {
        PrivateKey::deserialize_compressed(&bytes[..])
    }
}


//output is in little-endian
impl<P: Bls12Config> Into<String> for PrivateKey<P>{
    fn into(self) -> String {
        let mut serialized = vec![0; 32];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
impl<P: Bls12Config> Into<Vec<u8>> for PrivateKey<P>{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0; 32];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
    }
}

// impl<P: Bls12Config> AsRef<Fr> for PrivateKey<P> {
//     fn as_ref(&self) -> &Fr {
//         &self.0
//     }
// }

// impl<P: Bls12Config>  fmt::Debug for PrivateKey<P>{
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         write!(f, "{}", self.private_key)
//     }
// }

#[derive(Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<P: Bls12Config> {
    pub public_key: G1Projective<P>,
}
impl <P: Bls12Config> Default for PublicKey<P> {
    fn default() -> Self {
        PublicKey {
            public_key: G1Projective::<P>::default(),
        }
    }
}

impl <P: Bls12Config> Clone for PublicKey<P> {
    fn clone(&self) -> Self {
        PublicKey {
            public_key: self.public_key,
        }
    }
}

impl <P: Bls12Config> fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.public_key)
    }
}

impl <P: Bls12Config> std::cmp::Eq for PublicKey<P> {
    //TODO(keep), FIXME
    fn assert_receiver_is_total_eq(&self){}
}

impl <P: Bls12Config> std::cmp::PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }

    fn ne(&self, other: &Self) -> bool {
        self.public_key != other.public_key
    }
}

impl <P: Bls12Config> std::hash::Hash for PublicKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H){
        panic!("unimplemented");
    }
}

impl<P: Bls12Config> PublicKey<P>{
    pub fn aggregate(public_keys: &Vec<PublicKey<P>>) -> Option<PublicKey<P>> {
        if public_keys.len() == 0{
            None
        }else{
            Some(
                public_keys.into_iter()
                .map(|p| p.borrow().public_key)
                .sum::<G1Projective<P>>()
                .into())
        }
    }
}

impl<P: Bls12Config> From<G1Projective<P>> for PublicKey<P> {
    fn from(pk: G1Projective<P>) -> PublicKey<P> {
        Self {
            public_key: pk,
        }
    }
}

impl <P: Bls12Config>  AsRef<G1Projective<P>> for PublicKey<P> {
    fn as_ref(&self) -> &G1Projective<P> {
        &self.public_key
    }
}

impl<P: Bls12Config>  From<&PrivateKey<P>> for PublicKey<P> {
    fn from(sk: &PrivateKey<P>) -> PublicKey<P> {
        let generator = G1Projective::<P>::generator();
        let v = sk.private_key;
        PublicKey::from(generator.mul(v))
    }
}

//input MUST be in little-endian 
impl <P: Bls12Config>  TryFrom<&[u8]> for PublicKey<P>{
    type Error = SerializationError;
    fn try_from(bytes : &[u8]) -> Result<Self, SerializationError> {
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl <P: Bls12Config>  TryFrom<String> for PublicKey<P> {
    type Error = SerializationError;
    fn try_from(s:String) -> Result<Self, SerializationError> {
        let bytes: Vec<u8> = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl<P: Bls12Config>  TryFrom<&str> for PublicKey<P> {
    type Error = SerializationError;
    fn try_from(s:&str) -> Result<Self, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        PublicKey::deserialize_compressed(&bytes[..])
    }
}

//output is in little-endian
impl <P: Bls12Config> Into<String> for PublicKey<P>{
    fn into(self) -> String {
        let mut serialized = vec![0; 48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
impl <P: Bls12Config> Into<Vec<u8>> for PublicKey<P>{
    fn into(self) -> Vec<u8> {
        let mut serialized = vec![0;48];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        serialized
    }
}


#[derive(Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature <P: Bls12Config> {
    pub sig: G2Projective<P>,
}

impl <P: Bls12Config> Default for Signature<P> {
    fn default() -> Self {
        Signature {
            sig: G2Projective::<P>::default(),
        }
    }
}

impl <P: Bls12Config> Clone for Signature<P> {
    fn clone(&self) -> Self {
        Signature {
            sig: self.sig,
        }
    }
}


impl <P: Bls12Config> fmt::Debug for Signature<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.sig)
    }
}


impl <P: Bls12Config> Signature<P> {
    pub fn aggregate(signatures: &Vec<Signature<P>>) -> Option<Signature<P>> {
        if signatures.len() == 0{
            None
        }else{
            Some(
                signatures.into_iter()
                .map(|s| s.borrow().sig)
                .sum::<G2Projective<P>>()
                .into()
            )
        }
    }
}

impl <P: Bls12Config>  From<G2Projective<P>> for Signature<P> {
    fn from(sig: G2Projective<P>) -> Self {
        Self { sig }
    }
}

impl <P: Bls12Config> AsRef<G2Projective<P>> for Signature<P> {
    fn as_ref(&self) -> &G2Projective<P> {
        &self.sig
    }
}

//input MUST be in little-endian 
impl <P: Bls12Config>  TryFrom<&[u8]> for Signature<P>{
    type Error = SerializationError;
    fn try_from(bytes : &[u8]) -> Result<Self, SerializationError> {
        Signature::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string
impl <P: Bls12Config>  TryFrom<String> for Signature<P> {
    type Error = SerializationError;
    fn try_from(s:String) ->  Result<Self, SerializationError>  {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..])
    }
}

//input MUST be in little-endian hex string 
impl <P: Bls12Config>  TryFrom<&str> for Signature<P> {
    type Error = SerializationError;
    fn try_from(s:&str) -> Result<Self, SerializationError> {
        let bytes = hex::decode(s).unwrap();
        Signature::deserialize_compressed(&bytes[..])
    }
}

//output is in little-endian
impl <P: Bls12Config>  Into<String> for Signature<P>{
    fn into(self) -> String {
        let mut serialized = vec![0; 96];
        self.serialize_compressed(&mut serialized[..]).unwrap();
        hex::encode(serialized)
    }
}

//output is in little-endian
impl <P: Bls12Config>  Into<Vec<u8>> for Signature<P>{
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


pub struct BLS<P: Bls12Config> (PhantomData<P>);

impl<P> SignatureScheme for BLS<P> 
where
    P: Bls12Config,
    P::G2Config: WBConfig,
{
    type Parameters = Parameters<P>;
    type SecretKey = PrivateKey<P>;
    type PublicKey = PublicKey<P>;
    type Signature = Signature<P>;


    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Self::Parameters::default())
    }

    fn keygen<R: Rng>(
        _parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // security: it seems RFC 5869 implementation is not readily available in Arkworks,
        // so we will skip the salt here for now. Ref:
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html
   
        let rand =  <<P as Bls12Config>::G1Config as CurveConfig>::ScalarField::rand(rng);
        let private_key = Self::SecretKey{private_key: rand};
        // let private_key = Self::SecretKey::try_from(rand.to_string()).unwrap();
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
        if sk.private_key == Self::SecretKey::default().private_key {
            return Err(Box::new(BLSError::InvalidSecretKey))
        }
        let h   = G2Projective::<P>::from(hash_to_g2::<P>(message));
        let v = sk.private_key;
        h.mul(&v);
        let signature = Self::Signature::from(h.mul(v));

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        // security: identity test for public key
        if pk.public_key == Self::PublicKey::default().public_key {
            return Err(Box::new(BLSError::InvalidPublicKey))
        }
        // security: on-curve and prime order subgroup checks for public key and signature
        let pk_check = pk.public_key.check();
        match pk_check {
            Err(_) => return Err(Box::new(BLSError::InvalidPublicKey)),
            Ok(_) => {},
        }
        let sig_check = signature.sig.check();
        match sig_check {
            Err(_) => return Err(Box::new(BLSError::InvalidSignature)),
            Ok(_) => {},
        }

        let g1: G1Affine::<P> = parameters.g1_generator.clone().into();
        let g1_neg = G1Projective::<P>::from(g1.neg());

        let h: G2Projective<P> = hash_to_g2::<P>(message);
        
        let bls_paired = Bls12::<P>::multi_pairing([g1_neg, *pk.as_ref()], [*signature.as_ref(), h]);

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

pub fn hash_to_g2<P> (message: &[u8]) -> G2Projective<P> 
where
    P: Bls12Config,
    P::G2Config: WBConfig,
{
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let curve_hasher = MapToCurveBasedHasher::<
        ark_ec::short_weierstrass::Projective<P::G2Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<P::G2Config>
    >
    ::new(domain)
    .unwrap();

    let res = curve_hasher.hash(message).unwrap();

    G2Projective::<P>::from(res)
}

#[cfg(test)]
mod tests{
    use super::*;
    use ark_bls12_381::{Config, Fr};
    use ark_ff::BigInt;

    #[test]
    fn test_parameter_clone(){
        let p1 = Parameters::<Config>::default();
        let p2 = p1.clone();
        assert_eq!(p1.g1_generator, p2.g1_generator);
    }

    #[test]
    fn test_parameter_copy(){
        let p1 = Parameters::<Config>::default();
        let p2 = p1;
        let p3 = Parameters::<Config>::default();
        assert_eq!(p2.g1_generator, p3.g1_generator);
    }

    #[test]
    fn test_privatekey_clone(){
        let private_str= String::from("88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67");
        let p1 = PrivateKey::<Config>::try_from(private_str.clone()).unwrap();
        let p2 = p1.clone();
        assert_eq!(p1.private_key, p2.private_key);
    }

    #[test]
    fn test_privatekey_copy(){
        let private_str= String::from("88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67");
        let p1 = PrivateKey::<Config>::try_from(private_str.clone()).unwrap();
        let p2 = p1;
        let p3 = PrivateKey::<Config>::try_from(private_str.clone()).unwrap();
        assert_eq!(p2.private_key, p3.private_key);
    }

    #[test]
    fn test_publickey_clone(){
        let s= String::from("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
        let p1 = PublicKey::<Config>::try_from(s.clone()).unwrap();
        let p2 = p1.clone();
        assert_eq!(p1.public_key, p2.public_key);
    }

    #[test]
    fn test_publickey_copy(){
        let s= String::from("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
        let p1 = PublicKey::<Config>::try_from(s.clone()).unwrap();
        let p2 = p1;
        let p3 = PublicKey::<Config>::try_from(s.clone()).unwrap();
        assert_eq!(p2.public_key, p3.public_key);
    }


    #[test]
    fn test_signature_clone(){
        let s= String::from("b2cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e0");
        let s1 = Signature::<Config>::try_from(s.clone()).unwrap();
        let s2 = s1.clone();
        assert_eq!(s1.sig, s2.sig);
    }

    #[test]
    fn test_signature_copy(){
        let s= String::from("b2cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e0");
        let s1 = Signature::<Config>::try_from(s.clone()).unwrap();
        let s2 = s1;
        let s3 = Signature::<Config>::try_from(s.clone()).unwrap();
        assert_eq!(s2.sig, s3.sig);
    }
    


    #[test]
    fn test_privatekey_from_string(){
        /*
        private_key: PrivateKey(BigInt([12346421629811869064, 10832332258257352915, 17999185152888039383, 7443919619818212425]))
        private_str: "88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67"
        */
        
        //let expected_private_key = PrivateKey<Config>(Fr::from(BigInt([12346421629811869064, 10832332258257352915, 17999185152888039383, 7443919619818212425])));
        // println!("expected_private_key: {:?}", expected_private_key);
        let private_str= String::from("88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67");
        let private_key = PrivateKey::<Config>::try_from(private_str.clone()).unwrap();
        println!("private_key: {:?}", private_key);
        //assert_eq!(expected_private_key, private_key);
    
    
        let private_str_got:String = private_key.into();
        // println!("private_str_got: {:?}", private_str_got);
        assert_eq!(private_str, private_str_got);
    }


    #[test] 
    fn test_pubkey_from_string(){ 
        let s = String::from("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a");
        let pubkey = PublicKey::<Config>::try_from(s.clone()).unwrap();
        // println!("pubkey: {:?}", pubkey.pub_key);

        let got_s:String = pubkey.into();
        assert_eq!(s, got_s);
    }


    #[test]
    fn test_pubkey_from_privatekey(){
        let expected_private_key = PrivateKey::<Config>{
            private_key: Fr::from(BigInt([12346421629811869064, 10832332258257352915, 17999185152888039383, 7443919619818212425]))
        };
        // println!("expected_private_key: {:?}", expected_private_key);
        let private_str= String::from("88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67");
        let private_key = PrivateKey::<Config>::try_from(private_str.clone()).unwrap();
        // println!("private_key: {:?}", private_key);
        assert_eq!(expected_private_key.private_key, private_key.private_key);

        let pubkey =PublicKey::<Config>::from(&private_key);
        println!("pubkey: {:?}", pubkey.public_key);
        
    }

    #[test] 
    fn test_pubkey_aggregate(){ 
        let expected_aggregated_pubkey = String::from("88843ab5f8471de849950c06674238f68899e242cbc72f81bda95647caea52513139792c6511b18eaf2942d04fc54cae");
        let private_strs = [
            "88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e67",
            "88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e68",
            "88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e69",
            "88c522e40e4d57abd3386ff6cb2c5496d767606488f3c9f9494cd363741d4e6a"
        ];

        let mut pubic_keys = vec![];

        for private_str in private_strs {
            let private_key = PrivateKey::<Config>::try_from(private_str.clone().to_string()).unwrap();
            let pub_key = PublicKey::from(&private_key);
            pubic_keys.push(pub_key);
        }
        
        let aggregated_pubkey:String = PublicKey::aggregate(&pubic_keys).unwrap().into();
        assert_eq!(expected_aggregated_pubkey, aggregated_pubkey);
    }

    #[test]
    fn test_hash_to_g2(){
        let expected_hash = String::from("97502412bcfc3f1d88b71f1ad9b60fa37c332d19466fba1dc991d42bcd09bcd9f1c22a562646ffce0922793b6c69938b076e5cd6cfb3c361fc767e5f40ce05486e1668825ffeecab89d7daa455a179736a387ae93b9b15d283d45ffa14cd4af7");
        let message= [0u8;32];
        let hash:String = Signature::<Config>{sig: hash_to_g2::<Config>(&message)}.into();
        assert_eq!(expected_hash, hash);
    }
}