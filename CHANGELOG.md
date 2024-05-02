# viadkim changelog

All notable, publicly visible changes are listed in this changelog.

This project follows Rust-flavoured [semantic versioning], with changes to the
minimum supported Rust version being considered breaking changes.

[semantic versioning]: https://doc.rust-lang.org/cargo/reference/semver.html

## 0.2.0-alpha.3 (unreleased)

With this release, development has moved from GitLab to the [Codeberg] platform.

[Codeberg]: https://codeberg.org

### Changed

* When signing, specification of the *x=* tag is now done through field
  `SignRequest::expiration` taking an [`Expiration`] value, instead of the
  former field `SignRequest::valid_duration`. The new error variant
  `RequestError::ExpirationNotAfterTimestamp` indicates that *t=* and *x=*
  conflict.
* Canonicalized chunks returned by `BodyCanonicalizer` are now of type `Cow<'_,
  [u8]>` instead of `Vec<u8>`.

### Added

* The new convenience functions [`viadkim::sign`] and [`viadkim::verify`]
  encapsulate the most common usage pattern of `Signer` and `Verifier` in a
  single function call.
* The new module [`tag_list`] adds basic support for working with *tag=value
  lists*.
* The new associated functions `DkimSignature::from_tag_list` and
  `DkimKeyRecord::from_tag_list` parse their types from a `&TagList<'_>`.
* New type alias `SigningResult` represents signing output.
* New method `VerifyingKey::key_type` returns the key type of a verifying key.
* Missing API documentation has been filled in.

### Fixed

* *Relaxed* body canonicalization now produces the empty result for a completely
  blank body. (This change imposed itself after further testing and another
  close reading of the RFC, and follows the behaviour of OpenDKIM.)

[`Expiration`]: https://docs.rs/viadkim/0.2.0-alpha.2/viadkim/signer/enum.Expiration.html
[`viadkim::sign`]: https://docs.rs/viadkim/0.2.0-alpha.2/viadkim/signer/fn.sign.html
[`viadkim::verify`]: https://docs.rs/viadkim/0.2.0-alpha.2/viadkim/verifier/fn.verify.html
[`tag_list`]: https://docs.rs/viadkim/0.2.0-alpha.2/viadkim/tag_list/index.html

## 0.1.1 (2024-04-22)

### Fixed

* In both body canonicalization algorithms, a body consisting of only
  empty/blank lines is now correctly canonicalized to a single CRLF (`\r\n`).

## 0.1.0 (2023-11-24)

Initial release.
