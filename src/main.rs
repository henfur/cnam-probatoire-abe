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
    fs::remove_file,
    path::Path,
};

use rabe::error::RabeError;
use rocket::{
    serde::json::Json,
    form::Form,
    fs::TempFile
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

mod file_id;
use file_id::FileId;

//Network parameters
const LISTEN_ADDR: &'static str = "localhost";
const LISTEN_PORT: &'static str = "8000";
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

    let policy = String::from(&attributes);

    let keygen_res = keygen(PKG_MASTER_DIR_PATH, &policy);
    match keygen_res {
        Ok(secret_key) => secret_key,
        Err(e)=>{
            println!("Error msg is {}",e);
            "Could not generate secret key".to_string()
        }
    }
}

#[derive(FromForm)]
struct UploadData<'r> {
    file: TempFile<'r>,
    attributes: String
}

/// Handles APK files upload to the server
///
/// # Arguments
///
///	* `sent_file` - APK format file
/// * `_content_type` - Value of the Content-Type header from the HTTP request. Its value is checked beforehand by the RequestContentType implementation
///
// #[post("/uploadFile", format = "plain", data = "<upload_data>")]
#[post("/uploadFile", data = "<upload_data>")]
async fn upload_file(mut upload_data: Form<UploadData<'_>>) -> String {

    let id = FileId::new(32);
    let filename = format!("{upload_dir}{id}",upload_dir = UPLOAD_PATH, id = id);
    
    let filepath = Path::new(&filename);
    upload_data.file.copy_to(&filename).await;

    let encrypt_res = encrypt_file(PKG_MASTER_DIR_PATH, &filename, &upload_data.attributes);
    
    let msk_exists = filepath.exists();

    if msk_exists {
        remove_file(filepath);
    }
    match encrypt_res {
        Ok(())=> id.to_string(),
        Err(e)=>{
            println!("Error occured: {}", e);
            "Could not encrypt file".to_string()
        }
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
///	* `decryption_data` - JSON formated data matching the attributes of the FileData struct
///
#[post("/getFile", format = "application/json", data = "<decryption_data>")]
fn get_file(decryption_data: Json<DecryptionData>) -> Result<File, ()> {

    let mut file_path_string = "./upload/".to_string();
    file_path_string.push_str(&decryption_data.id);
    file_path_string.push_str(".ct");

    let decrypt_res = decrypt_file(&file_path_string, &decryption_data.secret_key);
    match decrypt_res {
        Ok(file)=> Ok(file),
        Err(_) => Err(())
    }
}