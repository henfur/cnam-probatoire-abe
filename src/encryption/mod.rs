//! Encryption module for mam-server (code/inspiration taken from the rabe-console application included in the rabe library)

extern crate rand;
extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde;

extern crate rustc_hex as hex;

use std::{fs::File};
use std::io::Write;

use hex::{FromHex, ToHex};
use crate::rabe::{
    error::RabeError,
    schemes::ac17,
    utils::{
        policy::pest::PolicyLanguage,
        file::{write_file, read_file, read_raw, read_to_vec}
    }
};

use serde::{
    de::DeserializeOwned,
    Serialize
};

use core::str;
use std::{
    path::Path, vec
};

use serde_cbor::{
    ser::to_vec_packed,
    from_slice
};

// File extensions
const CIPHERTEXT_EXTENSION: &'static str = "ct";
const KEY_EXTENSION: &'static str = "key";
const DOT: &'static str = ".";

// Default file names
const MASTER_SECRET_KEY_FILE: &'static str = "msk";
const PUBLIC_KEY_FILE: &'static str = "pk";
const SECRET_KEY_FILE: &'static str = "sk";

// Key file header and footer
const SK_BEGIN: &'static str = "-----BEGIN SK-----\n";
const SK_END: &'static str = "\n-----END SK-----";
const MSK_BEGIN: &'static str = "-----BEGIN MSK-----\n";
const MSK_END: &'static str = "\n-----END MSK-----";
const PK_BEGIN: &'static str = "-----BEGIN PK-----\n";
const PK_END: &'static str = "\n-----END PK-----";
const CT_BEGIN: &'static str = "-----BEGIN CT-----\n";
const CT_END: &'static str = "\n-----END CT-----";


pub fn setup_pkg(key_path: &str) -> Result<(), RabeError> {
    let mut master_secret_key_file = String::from("");
    let mut public_key_file = String::from("");
    let mut _gp_file = String::from("");
    
    master_secret_key_file.push_str(key_path);
    master_secret_key_file.push_str(&MASTER_SECRET_KEY_FILE);
    master_secret_key_file.push_str(&DOT);
    master_secret_key_file.push_str(&KEY_EXTENSION);
    
    public_key_file.push_str(key_path);
    public_key_file.push_str(&PUBLIC_KEY_FILE);
    public_key_file.push_str(&DOT);
    public_key_file.push_str(&KEY_EXTENSION);

    let (_pk, _msk) = ac17::setup();
    write_file(
        Path::new(&master_secret_key_file),
        ser_enc(_msk, MSK_BEGIN, MSK_END)
    );
    write_file(
        Path::new(&public_key_file),
        ser_enc(_pk, PK_BEGIN, PK_END)
    );
    Ok(())
}

pub fn keygen(
    pkg_master_path: &'static str,
    policy: &String
) -> Result<String, RabeError> {
    let mut secret_key_file = String::from("");
    
    let mut master_secret_key_file = String::from(pkg_master_path);
    master_secret_key_file.push_str(&MASTER_SECRET_KEY_FILE);
    master_secret_key_file.push_str(&DOT);
    master_secret_key_file.push_str(&KEY_EXTENSION);

    secret_key_file.push_str(&SECRET_KEY_FILE);
    secret_key_file.push_str(&DOT);
    secret_key_file.push_str(&KEY_EXTENSION);

    let _msk: ac17::Ac17MasterKey = match ser_dec(&master_secret_key_file) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };
    let _sk: ac17::Ac17KpSecretKey = ac17::kp_keygen(&_msk, policy, PolicyLanguage::JsonPolicy).unwrap();

    let secret_key_string: String = ser_enc(_sk, SK_BEGIN, SK_END);

    Ok(secret_key_string)
}

pub fn encrypt_file(
    pkg_master_path: &'static str,
    file_name: &String,
    attributes: &String
) -> Result<(), RabeError> {
    let mut public_key_file = String::from("");

    public_key_file.push_str(pkg_master_path);
    public_key_file.push_str(&PUBLIC_KEY_FILE);
    public_key_file.push_str(&DOT);
    public_key_file.push_str(&KEY_EXTENSION);

    let plaintext_file = String::from(file_name);
    let mut ciphertext_file = plaintext_file.to_string();
    ciphertext_file.push_str(&DOT);
    ciphertext_file.push_str(&CIPHERTEXT_EXTENSION);
 
    let buffer: Vec<u8> = read_to_vec(Path::new(&plaintext_file));

    let _public_key: ac17::Ac17PublicKey = match ser_dec(&public_key_file) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    let mut attributes_vector: Vec<String> = vec![];
    for attr in attributes.split(',') {
        attributes_vector.push(attr.to_string());
    }

    let ciphertext = ac17::kp_encrypt(&_public_key, &attributes_vector, &buffer).unwrap();

    write_file(
        Path::new(&ciphertext_file),
        ser_enc(&ciphertext, CT_BEGIN, CT_END)
    );

    Ok(())
}

pub fn decrypt_file(
    ciphertext_file: &String,
    encoded_secret_key: &String,
) -> Result<File, RabeError> {
    let plaintext_file: String = String::from("./tmp/plaintext_file");
    let plaintext_option: Result<Vec<u8>, RabeError>;

    let secret_key: ac17::Ac17KpSecretKey = match ser_dec_from_string(encoded_secret_key) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    let ciphertext: ac17::Ac17KpCiphertext = match ser_dec(ciphertext_file) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    plaintext_option = ac17::kp_decrypt(&secret_key, &ciphertext);
    let plaintext_file_path = Path::new(&plaintext_file);

    match plaintext_option {
        Err(e) => {
            return Err(e);
        }
        Ok(_pt_u) => {
            create_and_write_from_vec(&plaintext_file_path, &_pt_u);
            match File::open(&plaintext_file_path) {
                Ok(file) => Ok(file),
                Err(_) => Err(RabeError::new("Error opening plaintext file"))
            }
        }
    }
}

// Modified version of the utils function (Replace File::open by File::create)
fn create_and_write_from_vec(_file_path: &Path, _data: &Vec<u8>) {
    let display = _file_path.display();
    let mut file = match File::create(_file_path) {
        Err(why) => panic!("sorry, couldn't open {}: {}", display, why.to_string()),
        Ok(file) => file,
    };
    match file.write_all(&_data) {
        Err(why) => {
            panic!(
                "sorry, couldn't write to {}: {}",
                display,
                why.to_string()
            )
        }
        Ok(_) => println!("successfully wrote to {}", display),
    }
}

// Taken from rabe-console
fn ser_enc<T: Serialize>(input: T, head: &str, tail: &str) -> String {
    use deflate::deflate_bytes;
    [
        head.to_string(),
        deflate_bytes(
            &to_vec_packed(&input).unwrap()
        )
            .to_hex(),
        tail.to_string()
    ].concat()
}

// Taken from rabe-console
fn ser_dec<T: DeserializeOwned>(file_name: &String) -> Result<T, RabeError> {
    match ser_dec_bin_from_file(file_name) {
        Ok(parsed_bin) => match from_slice(&parsed_bin) {
            Ok(parsed_res) => Ok(parsed_res),
            Err(e) => return Err(RabeError::new(&format!("from_slice: {}", e.to_string().as_str())))
        },
        Err(e) => return Err(RabeError::new(&format!("ser_dec_bin: {}", e.to_string().as_str())))
    }
}

fn ser_dec_from_string<T: DeserializeOwned>(encoded_string: &String) -> Result<T, RabeError> {
    match ser_dec_bin_from_string(encoded_string) {
        Ok(parsed_bin) => match from_slice(&parsed_bin) {
            Ok(parsed_res) => Ok(parsed_res),
            Err(e) => return Err(RabeError::new(&format!("from_slice: {}", e.to_string().as_str())))
        },
        Err(e) => return Err(RabeError::new(&format!("ser_dec_bin: {}", e.to_string().as_str())))
    }
}


// Taken from rabe-console
fn ser_dec_bin_from_file(file_name: &String) -> Result<Vec<u8>, RabeError> {
    let string = read_raw(&read_file(Path::new(file_name)));
    ser_dec_bin_from_string(&string)
}

fn ser_dec_bin_from_string(encoded_string: &String) -> Result<Vec<u8>, RabeError> {
    use inflate::inflate_bytes;
    match encoded_string.from_hex::<Vec<u8>>() {
        Ok(byte_slice) => {
            match inflate_bytes(&byte_slice) {
                Ok(bytes) => Ok(bytes),
                Err(e) => return Err(RabeError::new(&format!("inflate_bytes: {}", e.to_string().as_str())))
            }
        },
        Err(e) => return Err(RabeError::new(&format!("read_raw: {}", e.to_string().as_str())))
    }
}