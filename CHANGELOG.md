# viadkim changelog

All notable, publicly visible changes are listed in this changelog.

This project follows Rust-flavoured [semantic versioning], with changes to the
minimum supported Rust version being considered breaking changes.

[semantic versioning]: https://doc.rust-lang.org/cargo/reference/semver.html

## 0.2.0-alpha.1 (2024-03-18)

### Changed

* When signing, specification of the *x=* tag is now done through field
  `SignRequest::expiration` taking an [`Expiration`] value, instead of the
  former `SignRequest::valid_duration`. The new error variant
  `RequestError::ExpirationNotAfterTimestamp` is used to signal that *t=* and
  *x=* conflict.

### Added

* The new module [`tag_list`] adds basic support for working with RFC 6376
  *tag=value lists*.
* Missing API documentation has been filled in.

[`Expiration`]: https://docs.rs/viadkim/0.2.0-alpha.1/viadkim/signer/enum.Expiration.html
[`tag_list`]: https://docs.rs/viadkim/0.2.0-alpha.1/viadkim/tag_list/index.html

## 0.1.0 (2023-11-24)

Initial release.
