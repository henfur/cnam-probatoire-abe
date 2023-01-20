#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

extern crate rabe;
extern crate deflate;
extern crate inflate;
extern crate serde;
extern crate serde_cbor;

extern crate rustc_hex as hex;

use std::{
    fs::{File, self},
};

use rabe::error::RabeError;
use rocket::{
    serde::json::Json,
    form::Form,
};

use serde::{
    Serialize,
    Deserialize
};

mod encryption;
use encryption::{
    encrypt_file,
    setup_pkg,
    keygen,
    decrypt_file
};

// File management constants
const UPLOAD_PATH: &'static str = "./upload/";
// PKG Parameters
const PKG_MASTER_DIR_PATH: &'static str = "./pkg/";

#[derive(FromForm, Deserialize, Serialize)]
struct UserData {
    username: String,
    api_key: String,
    attributes: String,
}

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

    rocket::build().mount("/", routes![get_secret_key, upload_file, get_file, get_shared_files])
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

use rocket::data::ToByteUnit;
use rocket::form::{self, FromFormField, DataField, ValueField};
// use memchr::memchr;

struct AppPkg<'r> {
    data: &'r [u8]
}

#[rocket::async_trait]
impl<'r> FromFormField<'r> for AppPkg<'r> {
    fn from_value(field: ValueField<'r>) -> form::Result<'r, Self> {
        Ok(
            AppPkg {data: field.value.as_bytes()}
        )
    }
    
    async fn from_data(field: DataField<'r, '_>) -> form::Result<'r, Self> {
        // Retrieve the configured data limit or use `256KiB` as default.
        let limit = field.request.limits()
            .get("app_pkg")
            .unwrap_or(256.mebibytes());

        // Read the capped data stream, returning a limit error as needed.
        let bytes = field.data.open(limit).into_bytes().await?;
        if !bytes.is_complete() {
            println!("Test");
            Err((None, Some(limit)))?;
        }

        // Store the bytes in request-local cache and split at ':'.
        let bytes = bytes.into_inner();
        let bytes = rocket::request::local_cache!(field.request, bytes);

        // Try to parse the name as UTF-8 or return an error if it fails.
        Ok(AppPkg { data: bytes })
    }
}

#[derive(FromForm)]
struct UploadData<'r> {
    policy: String,
    file: AppPkg<'r>
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
        Ok(file_id) => file_id,
        Err(e) => e.to_string()
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct DecryptionData{
    id: String,
    secret_key: String
}

/// Returns a plaintext file given the right secret key and file ID
/// TODO: Need to add a database to store the original associated to the encrypted file ID
/// # Arguments
///
///	* `decryption_data` - JSON formated data matching the attributes of the DecryptionData struct
///
#[post("/getFile", format = "application/json", data = "<decryption_data>")]
fn get_file(decryption_data: Json<DecryptionData>) -> Result<File, String> {

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