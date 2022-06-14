use std::{ffi::CStr, fs::File, io::Read, path::Path, ptr, str};

use crate::*;

use bson::{doc, Bson, Document};

unsafe fn with_binary_as_slice<T>(
    binary: *mut mongocrypt_binary_t,
    f: impl FnOnce(&[u8]) -> T,
) -> T {
    let data = mongocrypt_binary_data(binary);
    let len = mongocrypt_binary_len(binary);
    let slice = std::slice::from_raw_parts(data, len as usize);
    f(slice)
}

unsafe fn doc_from_binary(bytes: *mut mongocrypt_binary_t) -> Document {
    with_binary_as_slice(bytes, |slice| Document::from_reader(slice).unwrap())
}

unsafe fn with_slice_as_binary<T>(
    slice: &mut [u8],
    f: impl FnOnce(*mut mongocrypt_binary_t) -> T,
) -> T {
    let binary = mongocrypt_binary_new_from_data(slice.as_mut_ptr(), slice.len() as u32);
    let out = f(binary);
    mongocrypt_binary_destroy(binary);
    out
}

fn load_doc_from_json<P: AsRef<Path>>(path: P) -> Document {
    let file = File::open(path).unwrap();
    let json: serde_json::Value = serde_json::from_reader(file).unwrap();
    let bson = Bson::try_from(json).unwrap();
    match bson {
        Bson::Document(doc) => doc,
        _ => panic!("unexpected bson type"),
    }
}

struct BinaryBuffer {
    #[allow(dead_code)]
    bytes: Vec<u8>,
    binary: *mut mongocrypt_binary_t,
}

impl BinaryBuffer {
    fn read_json_as_bson<P: AsRef<Path>>(path: P) -> BinaryBuffer {
        let doc = load_doc_from_json(path);
        let mut bytes = Vec::new();
        doc.to_writer(&mut bytes).unwrap();
        let binary = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        BinaryBuffer { bytes, binary }
    }

    fn read_http<P: AsRef<Path>>(path: P) -> BinaryBuffer {
        let mut file = File::open(path).unwrap();
        let mut contents = vec![];
        file.read_to_end(&mut contents).unwrap();

        /* Copy and fix newlines: \n becomes \r\n. */
        let mut bytes = vec![];
        for i in 0..contents.len() {
            if contents[i] == b'\n' && contents[i - 1] != b'\r' {
                bytes.push(b'\r');
            }
            bytes.push(contents[i]);
        }

        let binary = unsafe {
            let ptr = bytes.as_mut_ptr() as *mut u8;
            mongocrypt_binary_new_from_data(ptr, bytes.len() as u32)
        };
        BinaryBuffer { bytes, binary }
    }
}

impl Drop for BinaryBuffer {
    fn drop(&mut self) {
        unsafe {
            mongocrypt_binary_destroy(self.binary);
        }
    }
}

unsafe fn run_state_machine(ctx: *mut mongocrypt_ctx_t) -> Document {
    let mut result = Document::new();
    loop {
        #[allow(non_upper_case_globals)]
        match mongocrypt_ctx_state(ctx) {
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_COLLINFO => {
                let output = mongocrypt_binary_new();
                assert!(mongocrypt_ctx_mongo_op(ctx, output));
                println!(
                    "\nrunning listCollections on mongod with this filter:\n{:?}",
                    doc_from_binary(output)
                );
                mongocrypt_binary_destroy(output);
                let input =
                    BinaryBuffer::read_json_as_bson("../testdata/collection-info.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    doc_from_binary(input.binary)
                );
                assert!(mongocrypt_ctx_mongo_feed(ctx, input.binary));
                assert!(mongocrypt_ctx_mongo_done(ctx));
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_MARKINGS => {
                let output = mongocrypt_binary_new();
                assert!(mongocrypt_ctx_mongo_op(ctx, output));
                println!(
                    "\nrunning cmd on mongocryptd with this schema:\n{:?}",
                    doc_from_binary(output)
                );
                mongocrypt_binary_destroy(output);
                let input =
                    BinaryBuffer::read_json_as_bson("../testdata/mongocryptd-reply.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    doc_from_binary(input.binary)
                );
                assert!(mongocrypt_ctx_mongo_feed(ctx, input.binary));
                assert!(mongocrypt_ctx_mongo_done(ctx));
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_MONGO_KEYS => {
                let output = mongocrypt_binary_new();
                assert!(mongocrypt_ctx_mongo_op(ctx, output));
                println!(
                    "\nrunning a find on the key vault coll with this filter:\n{:?}",
                    doc_from_binary(output)
                );
                mongocrypt_binary_destroy(output);
                let input = BinaryBuffer::read_json_as_bson("../testdata/key-document.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    doc_from_binary(input.binary)
                );
                assert!(mongocrypt_ctx_mongo_feed(ctx, input.binary));
                assert!(mongocrypt_ctx_mongo_done(ctx));
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_NEED_KMS => {
                loop {
                    let kms = mongocrypt_ctx_next_kms_ctx(ctx);
                    if kms == ptr::null_mut() {
                        break;
                    }
                    let output = mongocrypt_binary_new();
                    assert!(mongocrypt_kms_ctx_message(kms, output));
                    with_binary_as_slice(output, |slice| {
                        println!(
                            "sending the following to kms:\n{:?}",
                            str::from_utf8(slice).unwrap()
                        );
                    });
                    mongocrypt_binary_destroy(output);
                    let input = BinaryBuffer::read_http("../testdata/kms-decrypt-reply.txt");
                    println!(
                        "mocking reply from file:\n{:?}",
                        str::from_utf8(&input.bytes).unwrap()
                    );
                    assert!(mongocrypt_kms_ctx_feed(kms, input.binary));
                    assert_eq!(0, mongocrypt_kms_ctx_bytes_needed(kms));
                }
                mongocrypt_ctx_kms_done(ctx);
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_READY => {
                let output = mongocrypt_binary_new();
                assert!(mongocrypt_ctx_finalize(ctx, output));
                result = doc_from_binary(output);
                mongocrypt_binary_destroy(output);
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_DONE => {
                break;
            }
            mongocrypt_ctx_state_t_MONGOCRYPT_CTX_ERROR => {
                let status = mongocrypt_status_new();
                mongocrypt_ctx_status(ctx, status);
                let message = CStr::from_ptr(mongocrypt_status_message(status, ptr::null_mut()))
                    .to_str()
                    .unwrap()
                    .to_string();
                mongocrypt_status_destroy(status);
                panic!("got error: {}", message);
            }
            state => panic!("unhandled state {:?}", state),
        }
    }

    return result;
}

unsafe extern "C" fn log_to_stderr(
    level: mongocrypt_log_level_t,
    message: *const ::std::os::raw::c_char,
    _message_len: u32,
    _ctx: *mut ::std::os::raw::c_void,
) {
    #[allow(non_upper_case_globals)]
    let level_str = match level {
        mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_ERROR => "ERROR",
        mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_WARNING => "WARNING",
        mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_INFO => "INFO",
        mongocrypt_log_level_t_MONGOCRYPT_LOG_LEVEL_TRACE => "TRACE",
        _ => "UNKNOWN",
    };
    eprintln!("{}{}", level_str, CStr::from_ptr(message).to_str().unwrap());
}

fn cs(bytes: &'static [u8]) -> *const i8 {
    CStr::from_bytes_with_nul(bytes).unwrap().as_ptr()
}

unsafe fn init_test_crypt() -> *mut mongocrypt_t {
    let crypt = mongocrypt_new();
    mongocrypt_setopt_kms_provider_aws(crypt, cs(b"example\0"), -1, cs(b"example\0"), -1);
    mongocrypt_setopt_log_handler(crypt, Some(log_to_stderr), ptr::null_mut());
    if !mongocrypt_init(crypt) {
        panic!("failed to initialize");
    }
    crypt
}

#[test]
fn encryption_decryption() {
    unsafe {
        let crypt = init_test_crypt();

        // Encryption
        let ctx = mongocrypt_ctx_new(crypt);
        let msg = BinaryBuffer::read_json_as_bson("../testdata/cmd.json");
        mongocrypt_ctx_encrypt_init(ctx, cs(b"test\0"), -1, msg.binary);
        drop(msg);
        let result = run_state_machine(ctx);
        mongocrypt_ctx_destroy(ctx);

        // Decryption
        let ctx = mongocrypt_ctx_new(crypt);
        let mut input_bytes = vec![];
        result.to_writer(&mut input_bytes).unwrap();
        with_slice_as_binary(&mut input_bytes, |input| {
            mongocrypt_ctx_decrypt_init(ctx, input);
        });
        run_state_machine(ctx);
        mongocrypt_ctx_destroy(ctx);

        mongocrypt_destroy(crypt);
    }
}

#[test]
fn explicit_encryption_decryption() {
    unsafe {
        let crypt = init_test_crypt();

        // Encryption
        let ctx = mongocrypt_ctx_new(crypt);
        let mut key_doc = load_doc_from_json("../testdata/key-document.json");
        let key_bytes = match key_doc.get_mut("_id").unwrap() {
            Bson::Binary(bson::Binary { bytes, .. }) => bytes,
            _ => panic!("non-binary bson"),
        };
        with_slice_as_binary(key_bytes, |key_id| {
            mongocrypt_ctx_setopt_key_id(ctx, key_id);
        });
        mongocrypt_ctx_setopt_algorithm(ctx, cs(b"AEAD_AES_256_CBC_HMAC_SHA_512-Random\0"), -1);
        let wrapped = doc! { "v": "hello" };
        let mut wrapped_bytes = vec![];
        wrapped.to_writer(&mut wrapped_bytes).unwrap();
        with_slice_as_binary(&mut wrapped_bytes, |msg| {
            mongocrypt_ctx_explicit_encrypt_init(ctx, msg);
        });
        let result = run_state_machine(ctx);
        mongocrypt_ctx_destroy(ctx);

        // Decryption
        let ctx = mongocrypt_ctx_new(crypt);
        let mut input_bytes = vec![];
        result.to_writer(&mut input_bytes).unwrap();
        with_slice_as_binary(&mut input_bytes, |input| {
            mongocrypt_ctx_explicit_decrypt_init(ctx, input);
        });
        run_state_machine(ctx);
        mongocrypt_ctx_destroy(ctx);

        mongocrypt_destroy(crypt);
    }
}