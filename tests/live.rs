pub mod common;

use cmdkim::verifier::{Config, VerificationStatus};
use n0_dns_resolver::DnsResolver;
use std::sync::Arc;

/// Verify my signatures on a real message.
#[tokio::test]
#[ignore = "depends on live DNS records"]
async fn live_verify() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = Arc::new(DnsResolver::system_with_fallback());

    let msg = include_str!("messages/ci-chatmail.eml");

    let (header, body) = msg.split_once("\r\n\r\n").unwrap();

    let headers = header.parse().unwrap();

    let config = Config {
        allow_expired: true,
        ..Default::default()
    };

    let sigs = cmdkim::verify(&resolver, &headers, body.as_bytes(), &config).await;

    assert_eq!(sigs.len(), 1);

    for sig in sigs {
        assert_eq!(sig.status, VerificationStatus::Success);
    }
}
