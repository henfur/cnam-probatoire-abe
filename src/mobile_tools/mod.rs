use std::os::fd::AsRawFd;
use std::process::Command;
use uuid::Uuid;

use std::io::Write;
use memfile::{MemFile, CreateOptions, Seal};

use lazy_static::lazy_static;
use regex::Regex;

pub fn extract_android_app_label(apk_data: &[u8]) -> String {
    let file_id = Uuid::new_v4().as_simple().to_string();

    let mut temp_memfile = MemFile::create(&file_id, CreateOptions::new().allow_sealing(true)).unwrap();
    match temp_memfile.write_all(apk_data) {
        Ok(_) => {
            temp_memfile.add_seals(Seal::Write | Seal::Shrink | Seal::Grow).unwrap();

            let current_pid = std::process::id();
                    
            let mut apk_path_string = String::from("/proc/");
            apk_path_string.push_str(current_pid.to_string().as_str());
            apk_path_string.push_str("/fd/");
            apk_path_string.push_str(&temp_memfile.as_raw_fd().to_string().as_str());
            
            let aapt_output = Command::new("aapt2")
                .arg("dump")
                .arg("badging")
                .arg(&apk_path_string).output().expect("Failed");
                
            let output_string = String::from_utf8_lossy(&aapt_output.stdout).to_string();
        
            lazy_static! {
                static ref RE: Regex = Regex::new(r"application-label:'[a-zA-Z][0-9a-zA-Z_]*'").unwrap();
            }
        
            let mut app_label: String = String::from("");
            for cap in RE.captures_iter(&output_string) {
                let label: Vec<&str> = cap[0].split(":").collect();
                let mut label = label[1].chars();
                label.next();
                label.next_back();
                app_label.push_str(label.as_str());
            }
            app_label
        },
        Err(_) => String::from("")
    }

}