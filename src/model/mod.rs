use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;
use serde::{
    Deserialize
};

use crate::schema::users;
use crate::schema::ciphertext_files;

pub fn establish_connection() -> MysqlConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    MysqlConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

#[derive(Queryable, Debug, PartialEq, Eq, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub organization: String,
    pub department: String
}

#[derive(Insertable, Debug, PartialEq, Eq, Deserialize)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub email: &'a str
}

#[derive(Queryable, Insertable, Debug, PartialEq, Eq, Deserialize)]
#[diesel(table_name = ciphertext_files)]
pub struct CiphertextFile<'a> {
    pub original_file_name: &'a str,
    pub ciphertext_id: &'a str
}

pub fn create_user(conn: &mut MysqlConnection, username: &str, email: &str) -> () {

    let new_user = NewUser { username, email };

    diesel::insert_into(users::table)
        .values(&new_user)
        .execute(conn)
        .unwrap();
}

pub fn create_ciphertext_file(conn: &mut MysqlConnection, original_file_name: &str, ciphertext_id: &str) -> () {

    let new_ciphertext_file = CiphertextFile{ original_file_name, ciphertext_id };

    diesel::insert_into(ciphertext_files::table)
        .values(&new_ciphertext_file)
        .execute(conn)
        .unwrap();
}
