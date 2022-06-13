use std::path::Path;

use bson::doc;

use crate::{CryptBuilder, CryptoHooks};
use crate::error::Result;

mod binary;
mod error;

#[test]
fn builder_setopts() -> Result<()> {
    let builder = CryptBuilder::new();
    builder
        .log_handler(|level, msg| println!("{:?}: {}", level, msg))?
        .kms_providers(&doc! {})?
        .schema_map(&doc! {})?
        .encrypted_field_config_map(&doc! {})?
        .append_crypt_shared_lib_search_path(Path::new("$SYSTEM"))?
        .set_crypt_shared_lib_path_override(Path::new("$ORIGIN"))?
        .use_need_kms_credentials_state()
        .crypto_hooks(CryptoHooks {
            aes_256_cbc_encrypt: Box::new(|_, _, _, _| Ok(())),
            aes_256_cbc_decrypt: Box::new(|_, _, _, _| Ok(())),
            random: Box::new(|_, _| Ok(())),
            hmac_sha_512: Box::new(|_, _, _| Ok(())),
            hmac_sha_256: Box::new(|_, _, _| Ok(())),
            sha_256: Box::new(|_, _| Ok(())),
        })?
    ;
    Ok(())
}

#[test]
fn builder_build() -> Result<()> {
    let _crypt = CryptBuilder::new()
        .kms_provider_aws("example", "example")?
        .build()?;
    Ok(())
}

#[test]
fn crypt_shared_lib_version() -> Result<()> {
    let crypt = CryptBuilder::new()
        .kms_provider_aws("example", "example")?
        .build()?;
    assert_eq!(None, crypt.shared_lib_version());
    assert_eq!(None, crypt.shared_lib_version_string());
    Ok(())
}