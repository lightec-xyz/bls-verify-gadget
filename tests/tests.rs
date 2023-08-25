use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::Read;


fn read_files_in_directory(directory: &str) -> Result<Vec<String>, std::io::Error> {
    let mut file_contents = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
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
    let file_contents = read_files_in_directory("test_cases/sign")
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
    use ark_serialize::Compress;
    use bls_verify_gadget::bls::{PrivateKey, Parameters, BLS};

    use super::*;

    #[test]
    fn test_sign() {
        let test_cases = read_sign_test_cases();

        for (_, test_case) in test_cases.iter().enumerate() {    
            let private_bytes = hex::decode(&test_case.input.privkey[2..]).unwrap();
            let message_bytes = hex::decode(&test_case.input.message[2..]).unwrap();
            private_bytes.reverse();
            let private_key = PrivateKey::from(&private_bytes[..]);
            
            let parameters = Parameters::default();
            let mut rng = ark_std::test_rng();

            let signature = BLS::sign(&parameters, &private_key, &message_bytes, &mut rng).unwrap();
 
            let mut serialized = vec![0u8; 0];
            let mut size = 0;
            size += sig.serialized_size(Compress::Yes);
        
            serialized.resize(size, 0u8);
            sig.serialize_compressed(&mut serialized[..]).unwrap();
            assert_eq!(test_case.output, hex.encode(serialized));          
        }
    }
}

