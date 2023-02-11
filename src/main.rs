#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde;
extern crate serde_cbor;
extern crate memfile;

extern crate rustc_hex as hex;

use std::ffi::OsStr;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::{os, thread};
use std::{fs, os::fd::AsRawFd};
use std::process::Command;

use memfile::{MemFile, CreateOptions};
use model::{establish_connection};
use rabe::error::RabeError;
use rocket::Response;
use rocket::{
    serde::json::Json,
    form::Form,
    response::status
};

mod encryption;
use encryption::{
    encrypt_file,
    setup_pkg,
    keygen,
    decrypt_file
};

mod form_data;
use form_data::{
    DecryptionData,
    UploadData
};

pub mod model;
use model::*;
pub mod schema;


// File management constants
const UPLOAD_PATH: &'static str = "./upload/";
// PKG Parameters
const PKG_MASTER_DIR_PATH: &'static str = "./pkg/";


// Initializes PKG keys if they don't exist
// Starts the webserver
#[launch]
fn rocket() -> _ {
    let msk_exists = std::path::Path::new("./pkg/msk.key").try_exists();

    let init_pkg = match msk_exists {
        Ok(file_exists) => ! file_exists,
        Err(_) => panic!("Could not access pkg/ (Create the directories if they don't exist)"),
    };

    if init_pkg {
        let setup_res: Result<(), RabeError> = setup_pkg(&PKG_MASTER_DIR_PATH);

        match setup_res {
            Ok(_)=> (),
            Err(e)=>{
                println!("Error msg is {}",e);
            }
        }
    }

    rocket::build().mount("/", routes![get_secret_key, upload_file, get_file, get_shared_files, add_user])
}

#[get("/getSharedFiles")]
fn get_shared_files() -> String {
    let paths = fs::read_dir(UPLOAD_PATH).unwrap();

    let mut file_list = String::new();
    for path in paths {
        file_list = format!("{}{}", file_list, path.unwrap().path().display().to_string());
        file_list.push_str("\n");
    }
    return file_list;
}

/// Generates and sends secretKey to user
///
/// # Arguments
///
///	* `attributes` - String of attributes in the following format: "A,B"
///
#[post("/getSecretKey", format="text/plain", data="<attributes>")]
fn get_secret_key(attributes:  String) -> String {
    println!("Generating secret key for attributes : {}", &attributes);

    let keygen_res = keygen(PKG_MASTER_DIR_PATH, &attributes);
    match keygen_res {
        Ok(secret_key) => secret_key,
        Err(e)=>{
            println!("Error msg is {}",e);
            "Could not generate secret key".to_string()
        }
    }
}


use lazy_static::lazy_static;

use regex::Regex;

fn extract_android_app_label(input: &str) -> String {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"application-label:'[a-zA-Z][0-9a-zA-Z_]*'").unwrap();
    }
    let mut app_label: String = String::from("");
    for cap in RE.captures_iter(input) {
        let label: Vec<&str> = cap[0].split(":").collect();
        let mut label = label[1].chars();
        label.next();
        label.next_back();
        app_label.push_str(label.as_str());
    }
    app_label
}
/// Handles APK files upload to the server
///
/// # Arguments
///
///	* `upload_data` - UploadData struct matching the fields of the form 
///    - policy as a JSON string
///    - file as AppPkg struct 
///
#[post("/uploadFile", format = "multipart/form-data", data = "<upload_data>")]
fn upload_file(upload_data: Form<UploadData<'_>>) -> String {
    match encrypt_file(PKG_MASTER_DIR_PATH, upload_data.file.data, &upload_data.policy) {
        Ok(file_id) => {
            use std::io::Write;
            use memfile::{MemFile, CreateOptions, Seal};
            
            
            let mut temp_memfile = MemFile::create(&file_id, CreateOptions::new().allow_sealing(true)).unwrap();
            temp_memfile.write_all(upload_data.file.data);
            temp_memfile.add_seals(Seal::Write | Seal::Shrink | Seal::Grow).unwrap();
            
            let current_pid = std::process::id();
            println!("{}", std::process::id());
            
            let mut apk_path_string = String::from("/proc/");
            apk_path_string.push_str(current_pid.to_string().as_str());
            apk_path_string.push_str("/fd/");
            apk_path_string.push_str(&temp_memfile.as_raw_fd().to_string().as_str());
            
            println!("{}", apk_path_string);            
            let aapt_output = Command::new("aapt2")
                .arg("dump")
                .arg("badging")
                .arg(&apk_path_string).output().expect("Failed");
                
                let output_string = String::from_utf8_lossy(&aapt_output.stdout).to_string();
                
                let extracted_name = extract_android_app_label(&output_string);
                
                let mut app_name = String::new();
                if extracted_name.eq("") {
                    app_name.push_str("Unkown");
                } else {
                    app_name.push_str(extracted_name.as_str());
                }
                
                let conn = &mut establish_connection();
                create_ciphertext_file(conn, &app_name, &file_id.as_str());
                file_id
            }
            Err(e) => e.to_string()
        }
    }
    
    /// Returns a plaintext file given the right secret key and file ID
    /// TODO: Need to add a database to store the original associated to the encrypted file ID
    /// # Arguments
    ///
    ///	* `decryption_data` - JSON formated data matching the attributes of the DecryptionData struct
    ///
    #[post("/getFile", format = "application/json", data = "<decryption_data>")]
    fn get_file(decryption_data: Json<DecryptionData>) -> Result<Vec<u8>, String> {
        
    let mut file_path_string = UPLOAD_PATH.to_string();
    file_path_string.push_str(&decryption_data.id);
    file_path_string.push_str(".ct");

    let decrypt_res = decrypt_file(&file_path_string, &decryption_data.secret_key);
    match decrypt_res {
        Ok(file)=> {
            Ok(file)
        },
        Err(e) => Err(e.to_string())
    }
}

#[post("/addUser", format = "application/json", data="<user_creation_data>")]
fn add_user(user_creation_data: Json<NewUser>) -> Result<status::Accepted<&str>, status::Forbidden<()>> {
    let conn = &mut establish_connection();

    let username = user_creation_data.username;
    let email = user_creation_data.email;

    create_user(conn, username, email);

    Ok(status::Accepted(Some("User created")))
}