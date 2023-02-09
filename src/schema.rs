// @generated automatically by Diesel CLI.

diesel::table! {
    ciphertext_files (original_file_name, ciphertext_id) {
        original_file_name -> Varchar,
        ciphertext_id -> Varchar,
    }
}

diesel::table! {
    users (id) {
        id -> Unsigned<Bigint>,
        username -> Varchar,
        email -> Varchar,
        organization -> Nullable<Varchar>,
        department -> Nullable<Varchar>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    ciphertext_files,
    users,
);
