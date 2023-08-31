use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::Read;


fn read_files_in_directory(directory: &str) -> Result<Vec<String>, std::io::Error> {
    let mut file_contents = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.file_name().unwrap().to_str().unwrap().ends_with(".json") {
            let mut file = File::open(&path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            file_contents.push(content);
        }
    }

    Ok(file_contents)
}

#[derive(Debug, Deserialize, Serialize)]
struct SignTestCase {
    input: SignTestInput,
    output: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SignTestInput {
    privkey: String,
    message: String,
}

fn read_sign_test_cases() -> Vec<SignTestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/sign")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifyTestCase {
    input: VerifyTestInput,
    output: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifyTestInput {
    pubkey: String,
    message: String,
    signature: String,
}

fn read_verify_test_cases() -> Vec<VerifyTestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/verify")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[derive(Debug, Deserialize, Serialize)]
struct SignAggrTestCase {
    input: Vec<String>,
    output: Option<String>,
}

fn read_sign_aggr_test_cases() -> Vec<SignAggrTestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/aggregate")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[derive(Debug, Deserialize, Serialize)]
struct PubkeyAggrVerifyTestCase {
    input: PubkeyAggrVerifyTestInput,
    output: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct PubkeyAggrVerifyTestInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

fn read_pubkey_aggr_verify_test_cases() -> Vec<PubkeyAggrVerifyTestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/fast_aggregate_verify")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[derive(Debug, Deserialize, Serialize)]
struct DeserG1TestCase {
    input: DeserG1TestInput,
    output: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeserG1TestInput {
    pubkey: String,
}

fn read_deser_g1_test_cases() -> Vec<DeserG1TestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/deserialization_G1")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[derive(Debug, Deserialize, Serialize)]
struct DeserG2TestCase {
    input: DeserG2TestInput,
    output: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeserG2TestInput {
    signature: String,
}

fn read_deser_g2_test_cases() -> Vec<DeserG2TestCase> {
    let file_contents = read_files_in_directory("tests/test_cases/deserialization_G2")
        .unwrap_or_else(|err| panic!("Error reading test cases: {:?}", err));

    let mut test_cases = Vec::new();

    for content in file_contents {
        let test_case = serde_json::from_str(&content)
            .unwrap_or_else(|err| panic!("Error parsing test case: {:?}", err));
        
        test_cases.push(test_case);
    }

    test_cases
}

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::signature::SignatureScheme;
    use ark_serialize::{Compress, CanonicalSerialize};
    use bls_verify_gadget::bls::{PrivateKey, Parameters, BLS, PublicKey, Signature};

    use super::*;

    #[test]
    fn test_sign() {
        let test_cases = read_sign_test_cases();

        for test_case in test_cases {    
            let mut private_bytes = hex::decode(&test_case.input.privkey[2..]).unwrap();
            let message_bytes = hex::decode(&test_case.input.message[2..]).unwrap();
            private_bytes.reverse();
            let private_key = PrivateKey::try_from(&private_bytes[..]).unwrap();
            
            let parameters = Parameters::default();
            let mut rng = ark_std::test_rng();

            let sign_result = BLS::sign(&parameters, &private_key, &message_bytes, &mut rng);

            match test_case.output {
                None => if let Ok(_signature) = sign_result {
                    panic!("expected not to be signed, but signed");
                }
                Some(output) => {
                    let signature = sign_result.unwrap();

                    let mut serialized = vec![0u8; 0];
                    let mut size = 0;
                    size += signature.serialized_size(Compress::Yes);
        
                    serialized.resize(size, 0u8);
                    signature.serialize_compressed(&mut serialized[..]).unwrap();
                    assert_eq!(&output[2..], hex::encode(serialized));          
                }
            }
        }
    }

    #[test]
    fn test_verify() {
        let test_cases = read_verify_test_cases();

        for test_case in test_cases {
            let mut public_key = PublicKey::default();
            match PublicKey::try_from(&test_case.input.pubkey[2..]) {
                Ok(public_key_org) => public_key = public_key_org,
                Err(_err) => assert_eq!(test_case.output, false),
            }

            let mut signature = Signature::default();
            match Signature::try_from(&test_case.input.signature[2..]) {
                Ok(signature_org) => signature = signature_org,
                Err(_err) => assert_eq!(test_case.output, false),
            }

            let message_bytes = hex::decode(&test_case.input.message[2..]).unwrap();
            let parameters = Parameters::default();

            let res = match BLS::verify(&parameters, &public_key, &message_bytes, &signature) {
                Ok(sig_rlt) => sig_rlt,
                Err(_err) => false,
            };

            println!("test_case: {:?}, rst: {:?}", test_case, res);
            assert_eq!(test_case.output, res);
        }
    }

    #[test]
    fn test_sign_aggr() {
        let test_cases = read_sign_aggr_test_cases();

        for test_case in test_cases {
            let mut sigs = Vec::new();
            for sign_str in &test_case.input {
                sigs.push(Signature::try_from(&sign_str[2..]).unwrap());
            }

            let aggregated_sig = Signature::aggregate(&sigs);

            match test_case.output {
                None => if let Some(_aggr_sig) = aggregated_sig {
                    panic!("Expected the result of aggregate to be null, but not null");
                }
                Some(output) => {
                    let aggr_sig_str:String =  aggregated_sig.unwrap().into();
                    assert_eq!(&output[2..], &aggr_sig_str);
                }
            }
        }
    }

    #[test]
    fn test_pubkey_aggr_verify() {
        let test_cases = read_pubkey_aggr_verify_test_cases();

        for test_case in test_cases { 
            let mut signature = Signature::default();
            match Signature::try_from(&test_case.input.signature[2..]) {
                Ok(signature_org) => signature = signature_org,
                Err(_err) => assert_eq!(test_case.output, false),
            }

            let mut pubic_keys = Vec::new();
            for pubkey_str in &test_case.input.pubkeys {
                pubic_keys.push(PublicKey::try_from(&pubkey_str[2..]).unwrap());
            }

            let mut aggregated_pubkey = PublicKey::default();
            match PublicKey::aggregate(&pubic_keys) {
                Some(public_key_org) => aggregated_pubkey = public_key_org,
                None => assert_eq!(test_case.output, false),
            }
            
            let message_bytes = hex::decode(&test_case.input.message[2..]).unwrap();
            let parameters = Parameters::default();

            let res = match BLS::verify(&parameters, &aggregated_pubkey, &message_bytes, &signature) {
                Ok(sig_rlt) => sig_rlt,
                Err(_err) => false,
            };

            println!("test_case: {:?}, rst: {:?}", test_case, res);
            assert_eq!(test_case.output, res);
        }
    }

    #[test]
    fn test_deser_g1() {
        let test_cases = read_deser_g1_test_cases();

        for test_case in test_cases { 
            let deser_rst = match PublicKey::try_from(&test_case.input.pubkey[..]) {
                Ok(_pubkey) => true,
                Err(_err) => false,
            };
             
            println!("test_case: {:?}, rst: {:?}", test_case, deser_rst);
            assert_eq!(test_case.output, deser_rst);
        }
    }

    #[test]
    fn test_deser_g2() {
        let test_cases = read_deser_g2_test_cases();

        for test_case in test_cases { 
            let deser_rst = match Signature::try_from(&test_case.input.signature[..]) {
                Ok(_pubkey) => true,
                Err(_err) => false,
            };
            
            println!("test_case: {:?}, rst: {:?}", test_case, deser_rst);
            assert_eq!(test_case.output, deser_rst);
        }
    }

}

