pub mod common;

use common::MockLookup;
use std::io::ErrorKind;
use viadkim::{header::HeaderFields, verifier::VerificationStatus};

/// Example from RFC 8463, appendix A.
#[tokio::test]
async fn rfc8463_example() {
    let _ = tracing_subscriber::fmt::try_init();

    let resolver = MockLookup::new(|name| {
        Box::pin(async move {
            match name {
                "brisbane._domainkey.football.example.com." => Ok(vec![Ok(
                    "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
                )]),
                "test._domainkey.football.example.com." => Ok(vec![Ok(
                    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR\
iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC\
DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3\
Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
                        .into(),
                )]),
                _ => Err(ErrorKind::NotFound.into()),
            }
        })
    });

    let headers = make_header_fields();
    let body = make_body();
    let config = Default::default();

    let sigs = viadkim::verify(&resolver, &headers, &body, &config).await;

    assert_eq!(sigs.len(), 2);

    for sig in sigs {
        assert_eq!(sig.status, VerificationStatus::Success);
    }
}

fn make_header_fields() -> HeaderFields {
    "\
DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :
 date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>
"
    .parse()
    .unwrap()
}

fn make_body() -> Vec<u8> {
    "Hi.

We lost the game.  Are you hungry yet?

Joe.
"
    .replace('\n', "\r\n")
    .bytes()
    .collect()
}
