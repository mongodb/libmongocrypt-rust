use std::path::Path;

use bson::doc;

use crate::ctx::Algorithm;
use crate::error::Result;
use crate::CryptBuilder;

mod binary;
mod error;
mod example_state_machine;

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
        .crypto_hooks(
            |_, _, _, _| Ok(()),
            |_, _, _, _| Ok(()),
            |_, _| Ok(()),
            |_, _, _| Ok(()),
            |_, _, _| Ok(()),
            |_, _| Ok(()),
        )?
        .aes_256_ctr(|_, _, _, _| Ok(()), |_, _, _, _| Ok(()))?
        .aes_256_ecb(|_, _, _, _| Ok(()))?
        .crypto_hook_sign_rsassa_pkcs1_v1_5(|_, _, _| Ok(()))?
        .bypass_query_analysis();
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

#[test]
fn ctx_setopts() -> Result<()> {
    let crypt = CryptBuilder::new()
        .kms_provider_aws("example", "example")?
        .build()?;

    crypt.build_ctx(|builder| {
        builder
            .key_id(&[0; 16])?
            .key_alt_name("test")?
            .key_material(&[0; 96])?
            .algorithm(Algorithm::AeadAes256CbcHmacSha512Deterministic)?
            .masterkey_aws("somewhere", "something")?
            .masterkey_aws_endpoint("example.com")?
            .contention_factor(10)?
            .index_key_id(&bson::Uuid::new())?
            .query_type("equality")?
            .build_noop()
    })?;

    Ok(())
}
