use std::env;

fn main() {
    const LIB_DIR: &str = "MONGOCRYPT_LIB_DIR";
    println!("cargo:rerun-if-env-changed={}", LIB_DIR);

    println!("cargo:rustc-link-lib=dylib=mongocrypt");
    if let Ok(path) = env::var(LIB_DIR) {
        println!("cargo:rustc-link-search=native={}", path);
    }
}