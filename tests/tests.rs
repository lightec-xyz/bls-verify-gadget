use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

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

fn read_json_file(file_path: &str) -> Result<SignTestCase, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let parsed_data: SignTestCase = serde_json::from_str(&content)?;

    Ok(parsed_data)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

