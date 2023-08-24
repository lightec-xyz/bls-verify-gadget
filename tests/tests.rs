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



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

