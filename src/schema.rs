// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Unsigned<Bigint>,
        username -> Varchar,
        email -> Varchar,
        organization -> Nullable<Varchar>,
        department -> Nullable<Varchar>,
    }
}
