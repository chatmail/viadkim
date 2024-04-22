use std::{env, process};
use tokio::{
    fs,
    io::{self, AsyncReadExt},
};
use viadkim::{
    crypto::HashAlgorithm, signer::Expiration, DomainName, Selector, SignRequest, SigningAlgorithm,
    SigningKey, SigningOutput,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut args = env::args();

    let (key_file, domain, selector) = match (
        args.next().as_deref(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) {
        (_, Some(key_file), Some(domain), Some(selector), None) => (key_file, domain, selector),
        (program, ..) => {
            eprintln!(
                "usage: {} <key_file> <domain> <selector>",
                program.unwrap_or("dkimsign")
            );
            process::exit(1);
        }
    };

    let key_file = fs::read_to_string(key_file).await.unwrap();
    let domain = DomainName::new(domain).unwrap();
    let selector = Selector::new(selector).unwrap();

    let signing_key = SigningKey::from_pkcs8_pem(&key_file).unwrap();
    let algorithm =
        SigningAlgorithm::from_parts(signing_key.key_type(), HashAlgorithm::Sha256).unwrap();

    let mut request = SignRequest::new(domain, selector, algorithm, signing_key);
    request.expiration = Expiration::Never;
    //
    // Experiment with the various configuration options here.
    //
    // request.copy_headers = true;
    // request.body_length = viadkim::signer::BodyLength::MessageContent;
    // request.identity = Some(viadkim::signature::Identity::new("\"abc|;привет\"@中文.example.com").unwrap());
    // request.algorithm = SigningAlgorithm::RsaSha1;
    // request.format.tag_order = Some(Box::new(|a, b| a.cmp(b)));
    // request.format.line_width = 64.try_into().unwrap();
    // request.format.indentation = "  ".into();
    // request.format.ascii_only = true;
    // request.ext_tags = vec![("r".into(), "y".into())];

    let mut msg = String::new();
    let n = io::stdin().read_to_string(&mut msg).await.unwrap();
    assert!(n > 0, "empty message on stdin");

    let msg = msg.split("\r\n")
        .flat_map(|s| s.split('\n'))
        .collect::<Vec<_>>()
        .join("\r\n");

    let (header, body) = msg.split_once("\r\n\r\n").unwrap();

    let header = header.parse().unwrap();
    let body = body.as_bytes();

    let sigs = viadkim::sign(header, body, [request]).await.unwrap();

    for sig in sigs {
        match sig {
            Ok(SigningOutput { header_name, header_value, .. }) => {
                let header_value = header_value.replace("\r\n", "\n");
                println!("{header_name}:{header_value}");
            }
            Err(e) => {
                eprintln!("failed to sign: {e}");
                process::exit(1);
            }
        }
    }
}
