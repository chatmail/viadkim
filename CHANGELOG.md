# viadkim changelog

All notable, publicly visible changes are listed in this changelog.

This project follows Rust-flavoured [semantic versioning], with changes to the
minimum supported Rust version being considered breaking changes.

[semantic versioning]: https://doc.rust-lang.org/cargo/reference/semver.html

## 0.2.0 (unreleased)

### Changed

* When signing, specification of the *x=* tag is now done through field
  `SignRequest::expiration` taking an `Expiration` value, instead of the former
  `SignRequest::valid_duration`. The new error variant
  `RequestError::TimestampNotBeforeExpiration` is used to signal that *t=* and
  *x=* conflict.

## 0.1.0 (2023-11-24)

Initial release.
