use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;
use serde::{
    Deserialize
};

use crate::schema::users;

pub fn establish_connection() -> MysqlConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_HOST").expect("DATABASE_HOST must be set");
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

pub fn create_user(conn: &mut MysqlConnection, username: &str, email: &str) -> User {

    let new_user = NewUser { username, email };

    diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Error saving new user")
}
