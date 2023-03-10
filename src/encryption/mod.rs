//! Encryption module for mam-server (code/inspiration taken from the rabe-console application included in the rabe library)

extern crate rand;
extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde;

extern crate rustc_hex as hex;

use hex::{FromHex, ToHex};
use crate::rabe::{
    error::RabeError,
    schemes::ac17,
    utils::{
        policy::pest::PolicyLanguage,
        file::{write_file, read_file, read_raw}
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

use uuid::Uuid;

// File extensions
const CIPHERTEXT_EXTENSION: &'static str = ".ct";

// Default file names
const MASTER_SECRET_KEY_FILE: &'static str = "msk.key";
const PUBLIC_KEY_FILE: &'static str = "pk.key";

//Uploads
const UPLOAD_PATH: &'static str = "upload/";

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
    
    master_secret_key_file.push_str(key_path);
    master_secret_key_file.push_str(&MASTER_SECRET_KEY_FILE);
    
    public_key_file.push_str(key_path);
    public_key_file.push_str(&PUBLIC_KEY_FILE);

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
    attributes: &String
) -> Result<String, RabeError> {
    
    let mut master_secret_key_file = String::from(pkg_master_path);
    master_secret_key_file.push_str(&MASTER_SECRET_KEY_FILE);

    let master_secret_key: ac17::Ac17MasterKey = match ser_dec(&master_secret_key_file) {
        Ok(parsed) => parsed,
        Err(e) => panic!("{}", e.to_string())
    };
    println!("... done");
    print!("creating AC17CP sk for {:?} ...", attributes);

    let mut attributes_vector: Vec<String> = vec![];
    for attr in attributes.split(',') {
        attributes_vector.push(attr.to_string());
    }
    
    let secret_key: ac17::Ac17CpSecretKey = ac17::cp_keygen(&master_secret_key, &attributes_vector).unwrap();

    Ok(ser_enc(secret_key, SK_BEGIN, SK_END))
}

pub fn encrypt_file(
    pkg_master_path: &'static str,
    file_buffer: &[u8],
    policy: &String
) -> Result<String, RabeError> {
    let mut public_key_file = String::from("");

    public_key_file.push_str(pkg_master_path);
    public_key_file.push_str(&PUBLIC_KEY_FILE);

    let file_id = Uuid::new_v4().as_simple().to_string();
    let mut ciphertext_file = String::from(UPLOAD_PATH.to_string());
    ciphertext_file.push_str(file_id.as_str());
    ciphertext_file.push_str(&CIPHERTEXT_EXTENSION);
 
    let public_key: ac17::Ac17PublicKey = match ser_dec(&public_key_file) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    let ciphertext = ac17::cp_encrypt(&public_key, &policy, file_buffer, PolicyLanguage::JsonPolicy).unwrap();

    write_file(
        Path::new(&ciphertext_file),
        ser_enc(&ciphertext, CT_BEGIN, CT_END)
    );

    Ok(file_id)
}

pub fn decrypt_file(
    ciphertext_file: &String,
    encoded_secret_key: &String,
) -> Result<Vec<u8>, RabeError> {
    let plaintext_option: Result<Vec<u8>, RabeError>;

    let secret_key: ac17::Ac17CpSecretKey = match ser_dec_from_string(encoded_secret_key) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    let ciphertext: ac17::Ac17CpCiphertext = match ser_dec(ciphertext_file) {
        Ok(parsed) => parsed,
        Err(e) => return Err(e)
    };

    plaintext_option = ac17::cp_decrypt(&secret_key, &ciphertext);

    match plaintext_option {
        Err(e) => {
            Err(RabeError::new(e.to_string().as_str()))
        }
        Ok(_pt_u) => Ok(_pt_u)
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