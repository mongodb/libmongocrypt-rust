use std::{path::Path, fs::File, io::Read};

use bson::{Document, Bson, RawDocument, RawDocumentBuf};

use crate::{ctx::{Ctx, State, Algorithm}, error::Result, Crypt};

fn load_doc_from_json<P: AsRef<Path>>(path: P) -> Document {
    let file = File::open(path).unwrap();
    let json: serde_json::Value = serde_json::from_reader(file).unwrap();
    let bson = Bson::try_from(json).unwrap();
    match bson {
        Bson::Document(doc) => doc,
        _ => panic!("unexpected bson type"),
    }
}

fn read_json_as_bson<P: AsRef<Path>>(path: P) -> RawDocumentBuf {
    let doc = load_doc_from_json(path);
    let mut bytes = Vec::new();
    doc.to_writer(&mut bytes).unwrap();
    RawDocumentBuf::from_bytes(bytes).unwrap()
}

fn read_http<P: AsRef<Path>>(path: P) -> Vec<u8> {
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

    bytes
}

fn raw_to_doc(raw: &RawDocument) -> Document {
    raw.try_into().unwrap()
}

fn run_state_machine(ctx: &mut Ctx) -> Result<RawDocumentBuf> {
    let mut result = RawDocumentBuf::new();
    loop {
        match ctx.state()? {
            State::NeedMongoCollinfo => {
                let output = ctx.mongo_op()?;
                println!(
                    "\nrunning listCollections on mongod with this filter:\n{:?}",
                    raw_to_doc(output),
                );
                let input = read_json_as_bson("../testdata/collection-info.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    raw_to_doc(&input),
                );
                ctx.mongo_feed(&input)?;
                ctx.mongo_done()?;
            }
            State::NeedMongoMarkings => {
                let output = ctx.mongo_op()?;
                println!(
                    "\nrunning cmd on mongocryptd with this schema:\n{:?}",
                    raw_to_doc(output),
                );
                let input = read_json_as_bson("../testdata/mongocryptd-reply.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    raw_to_doc(&input),
                );
                ctx.mongo_feed(&input)?;
                ctx.mongo_done()?;
            }
            State::NeedMongoKeys => {
                let output = ctx.mongo_op()?;
                println!(
                    "\nrunning a find on the key vault coll with this filter:\n{:?}",
                    raw_to_doc(output),
                );
                let input = read_json_as_bson("../testdata/key-document.json");
                println!(
                    "\nmocking reply from file:\n{:?}",
                    raw_to_doc(&input),
                );
                ctx.mongo_feed(&input)?;
                ctx.mongo_done()?;
            }
            State::NeedKms => {
                let mut scope = ctx.kms_scope();
                while let Some(mut kms) = scope.next_kms_ctx() {
                    let output = kms.message()?;
                    println!(
                        "sending the following to kms:\n{:?}",
                        std::str::from_utf8(output)?,
                    );
                    let input = read_http("../testdata/kms-decrypt-reply.txt");
                    println!(
                        "mocking reply from file:\n{:?}",
                        std::str::from_utf8(&input)?,
                    );
                    kms.feed(&input)?;
                    assert_eq!(0, kms.bytes_needed());
                }
                ctx.kms_done(scope)?;
            }
            State::Ready => {
                let output = ctx.finalize()?;
                result = output.to_owned();
            }
            State::Done => break,
            State::NeedKmsCredentials => panic!("unexpected state"),
        }
    }
    Ok(result)
}

fn init_test_crypt() -> Result<Crypt> {
    Crypt::builder()
        .kms_provider_aws("example", "example")?
        .log_handler(|level, message| eprintln!("{:?}: {}", level, message))?
        .build()
}

#[test]
fn encryption_decryption() -> Result<()> {
    let crypt = init_test_crypt()?;

    // Encryption
    let msg = read_json_as_bson("../testdata/cmd.json");
    let mut ctx = crypt.ctx_builder()
        .build_encrypt("test", &msg)?;
    let result = run_state_machine(&mut ctx)?;

    // Decryption
    let mut ctx = crypt.ctx_builder()
        .build_decrypt(&result)?;
    run_state_machine(&mut ctx)?;

    Ok(())
}

#[test]
fn explicit_encryption_decryption() -> Result<()> {
    let crypt = init_test_crypt()?;

    // Encryption
    let key_doc = load_doc_from_json("../testdata/key-document.json");
    let key_bytes = match key_doc.get("_id").unwrap() {
        Bson::Binary(bson::Binary { bytes, .. }) => bytes,
        _ => panic!("non-binary bson"),
    };
    let mut ctx = crypt.ctx_builder()
        .key_id(key_bytes)?
        .algorithm(Algorithm::AeadAes256CbcHmacSha512Random)?
        .build_explicit_encrypt(&Bson::String("hello".to_string()))?;
    let result = run_state_machine(&mut ctx)?;

    // Decryption
    let mut ctx = crypt.ctx_builder()
        .build_explicit_decrypt(result.as_bytes())?;
    run_state_machine(&mut ctx)?;

    Ok(())
}