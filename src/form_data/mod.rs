use rocket::data::ToByteUnit;
use rocket::form::{self, FromFormField, DataField, ValueField};

use serde::{
    Deserialize
};

pub struct AppPkg<'r> {
    pub data: &'r [u8]
}

#[rocket::async_trait]
impl<'r> FromFormField<'r> for AppPkg<'r> {
    fn from_value(field: ValueField<'r>) -> form::Result<'r, Self> {
        Ok(
            AppPkg {data: field.value.as_bytes()}
        )
    }
    
    async fn from_data(field: DataField<'r, '_>) -> form::Result<'r, Self> {
        let limit = field.request.limits()
            .get("app_pkg")
            .unwrap_or(256.mebibytes());

        let bytes = field.data.open(limit).into_bytes().await?;
        if !bytes.is_complete() {
            Err((None, Some(limit)))?;
        }

        let bytes = bytes.into_inner();
        let bytes = rocket::request::local_cache!(field.request, bytes);

        Ok(AppPkg { data: bytes })
    }
}

#[derive(FromForm)]
pub struct UploadData<'r> {
    pub policy: String,
    pub file: AppPkg<'r>
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct DecryptionData{
    pub app_name: String,
    pub secret_key: String
}

// #[derive(FromForm, Deserialize, Serialize)]
// pub struct UserData {
//     username: String,
//     api_key: String,
//     attributes: String,
// }
