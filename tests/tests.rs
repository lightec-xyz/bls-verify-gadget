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
            let private_key = PrivateKey::from(&private_bytes[..]);
            
            let parameters = Parameters::default();
            let mut rng = ark_std::test_rng();

            let sign_result = BLS::sign(&parameters, &private_key, &message_bytes, &mut rng);

            match test_case.output {
                None => if let Ok(signature) = sign_result {
                    panic!("expected not to be signed, but signed")
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
            let message_bytes = hex::decode(&test_case.input.message[2..]).unwrap();
           
            let parameters = Parameters::default();
            let public_key = PublicKey::from(&test_case.input.pubkey[2..]);
            let signature = Signature::from(&test_case.input.signature[2..]);


            let res = BLS::verify(&parameters, &public_key, &message_bytes, &signature).unwrap();
            assert_eq!(test_case.output, res);
        }
    }

    #[test]
    fn test_sign_aggr() {
        let test_cases = read_sign_aggr_test_cases();

        for test_case in test_cases {
            let mut sigs = Vec::new();
            for sign_str in test_case.input {
                sigs.push(Signature::from(&sign_str[2..]));
            }

            let aggregated_sig = Signature::aggregate(sigs);

            match test_case.output {
                None => {
                    // todo
                    panic!("Signature aggregate does not handle when the input is null")
                }
                Some(output) => {
                    let aggr_sig_str: String =  aggregated_sig.into(); 
                    assert_eq!(output[2..], aggr_sig_str);
                }
            }
        }
    }
}

