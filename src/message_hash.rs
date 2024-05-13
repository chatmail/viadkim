// viadkim – implementation of the DKIM specification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

//! Computation of the message hashes.
//!
//! Use [`compute_data_hash`] to compute the *data hash*, and [`BodyHasher`] to
//! compute the *body hash* (see RFC 6476, section 3.7).

use crate::{
    canonicalize::{self, BodyCanonicalizer},
    crypto::{self, CountingHasher, HashAlgorithm, HashStatus, InsufficientInput},
    header::{FieldName, HeaderFields},
    signature::{CanonicalizationAlgorithm, DkimSignature},
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display, Formatter},
};

/// Computes the *data hash* for the given inputs.
pub fn compute_data_hash(
    hash_alg: HashAlgorithm,
    canon_alg: CanonicalizationAlgorithm,
    headers: &HeaderFields,
    selected_headers: &[FieldName],
    dkim_sig_header_name: &str,
    formatted_dkim_sig_header_value: &str,
) -> Box<[u8]> {
    // canonicalize selected headers
    let mut cheaders = canonicalize::canonicalize_headers(canon_alg, headers, selected_headers);

    // canonicalize DKIM-Signature header
    canonicalize::canonicalize_header(
        &mut cheaders,
        canon_alg,
        dkim_sig_header_name,
        formatted_dkim_sig_header_value,
    );

    // produce message digest of the canonicalized value
    crypto::digest(hash_alg, &cheaders)
}

/// The stance of a body hasher regarding additional body content.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
pub enum BodyHasherStance {
    // Note: the stance does not represent the ultimate truth: `Done` means it
    // is definitely done, but `Interested` is not necessarily true, because the
    // `BodyCanonicalizer`s are stateful and may already have the final pieces.

    /// When `Interested` is returned after digesting input, then the client
    /// should feed more inputs to the body hasher, if there are any available
    /// still.
    Interested,

    /// When `Done` is returned after digesting input, the body hasher requires
    /// no further inputs to answer all body hash requests, and the client need
    /// not feed any additional inputs to the body hasher even if there is any
    /// remaining.
    Done,
}

/// A key referencing a body hash request in a `BodyHasher`.
pub type BodyHasherKey = (Option<usize>, HashAlgorithm, CanonicalizationAlgorithm);

/// Constructs a `BodyHasherKey` from DKIM signature data.
///
/// # Panics
///
/// Panics if the DKIM signature’s `body_length` value does not fit in a
/// `usize`.
pub fn body_hasher_key(sig: &DkimSignature) -> BodyHasherKey {
    let body_len = sig.body_length
        .map(|len| len.try_into().expect("integer overflow"));
    let hash_alg = sig.algorithm.hash_algorithm();
    let canon_alg = sig.canonicalization.body;
    (body_len, hash_alg, canon_alg)
}

/// A builder for body hashers.
#[derive(Clone)]
pub struct BodyHasherBuilder {
    fail_on_truncate: bool,  // truncated inputs must yield InputTruncated
    registrations: HashSet<BodyHasherKey>,
}

impl BodyHasherBuilder {
    /// Creates a new builder for a body hasher.
    ///
    /// The argument controls whether the resulting body hasher will accept or
    /// reject only partially hashed message bodies.
    pub fn new(fail_on_partially_hashed_input: bool) -> Self {
        Self {
            fail_on_truncate: fail_on_partially_hashed_input,
            registrations: HashSet::new(),
        }
    }

    /// Registers a body hash request, ie the tuple (length limit of body
    /// content, hash algorithm, body canonicalization algorithm).
    pub fn register_canonicalization(
        &mut self,
        len: Option<usize>,
        hash: HashAlgorithm,
        canon: CanonicalizationAlgorithm,
    ) {
        self.registrations.insert((len, hash, canon));
    }

    /// Builds a body hasher that can answer all registered body hash requests.
    pub fn build(self) -> BodyHasher {
        use CanonicalizationAlgorithm::*;

        let hashers = self.registrations.into_iter()
            .map(|key @ (len, hash, _)| (key, (CountingHasher::new(hash, len), false)))
            .collect();

        BodyHasher {
            fail_on_truncate: self.fail_on_truncate,
            hashers,
            canonicalizer_simple: BodyCanonicalizer::new(Simple),
            canonicalizer_relaxed: BodyCanonicalizer::new(Relaxed),
        }
    }
}

/// A producer of *body hash* results.
///
/// The body hasher canonicalizes and hashes chunks of the message body, until
/// all body hash requests can be answered. The main benefits of the body hasher
/// design are deduplication of the canonicalization and hashing effort, and
/// shortcutting the computation when only part of the message body is of
/// interest.
pub struct BodyHasher {
    fail_on_truncate: bool,
    // For each registration/key, map to a hasher and a flag that records
    // whether input was truncated, ie only partially consumed.
    hashers: HashMap<BodyHasherKey, (CountingHasher, bool)>,
    canonicalizer_simple: BodyCanonicalizer,
    canonicalizer_relaxed: BodyCanonicalizer,
}

impl BodyHasher {
    /// Canonicalizes and hashes a chunk of the message body.
    pub fn hash_chunk(&mut self, chunk: &[u8]) -> BodyHasherStance {
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut all_done = true;

        let active_hashers = self.hashers.iter_mut().filter(|(_, (hasher, truncated))| {
            !hasher.is_done() || (self.fail_on_truncate && !truncated)
        });

        for ((_, _, canon), (hasher, truncated)) in active_hashers {
            let canonicalized_chunk = match canon {
                CanonicalizationAlgorithm::Simple => canonicalized_chunk_simple
                    .get_or_insert_with(|| self.canonicalizer_simple.canonicalize_chunk(chunk)),
                CanonicalizationAlgorithm::Relaxed => canonicalized_chunk_relaxed
                    .get_or_insert_with(|| self.canonicalizer_relaxed.canonicalize_chunk(chunk)),
            };

            match hasher.update(canonicalized_chunk) {
                HashStatus::AllConsumed => {
                    if self.fail_on_truncate || !hasher.is_done() {
                        all_done = false;
                    }
                }
                HashStatus::Truncated => {
                    *truncated = true;
                }
            }
        }

        if all_done {
            BodyHasherStance::Done
        } else {
            BodyHasherStance::Interested
        }
    }

    /// Finalises any body hash calculations still in progress and returns the
    /// results.
    pub fn finish(self) -> BodyHashResults {
        let mut finish_canonicalization_simple = Some(|| self.canonicalizer_simple.finish());
        let mut finish_canonicalization_relaxed = Some(|| self.canonicalizer_relaxed.finish());
        let mut canonicalized_chunk_simple = None;
        let mut canonicalized_chunk_relaxed = None;

        let mut results = HashMap::new();

        for (key @ (_, _, canon), (mut hasher, mut truncated)) in self.hashers {
            if !hasher.is_done() || (self.fail_on_truncate && !truncated) {
                let canonicalized_chunk = match canon {
                    CanonicalizationAlgorithm::Simple => {
                        match finish_canonicalization_simple.take() {
                            Some(f) => canonicalized_chunk_simple.insert(f()),
                            None => canonicalized_chunk_simple.as_ref().unwrap(),
                        }
                    }
                    CanonicalizationAlgorithm::Relaxed => {
                        match finish_canonicalization_relaxed.take() {
                            Some(f) => canonicalized_chunk_relaxed.insert(f()),
                            None => canonicalized_chunk_relaxed.as_ref().unwrap(),
                        }
                    }
                };

                if let HashStatus::Truncated = hasher.update(canonicalized_chunk) {
                    truncated = true;
                }
            }

            let res = if self.fail_on_truncate && truncated {
                Err(BodyHashError::InputTruncated)
            } else {
                hasher.finish().map_err(|InsufficientInput| BodyHashError::InsufficientInput)
            };

            results.insert(key, res);
        }

        BodyHashResults { results }
    }
}

/// An error that occurs when computing the *body hash*.
///
/// These errors can only occur when the *l=* tag is used.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyHashError {
    /// Less than the expected input data have been fed to the body hasher.
    InsufficientInput,
    /// The input was only partially consumed by the body hasher.
    InputTruncated,
}

impl Display for BodyHashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientInput => write!(f, "insufficient input data"),
            Self::InputTruncated => write!(f, "input not digested entirely"),
        }
    }
}

impl Error for BodyHashError {}

/// A result answering a body hash request.
///
/// The result contains the final body hash (digest) and the number of bytes
/// digested.
pub type BodyHashResult = Result<(Box<[u8]>, usize), BodyHashError>;

/// Results produced by a body hasher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyHashResults {
    results: HashMap<BodyHasherKey, BodyHashResult>,
}

impl BodyHashResults {
    /// Returns the result computed for a given body hash request.
    pub fn get(&self, key: &BodyHasherKey) -> Option<&BodyHashResult> {
        self.results.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{signature::CanonicalizationAlgorithm::*, util};
    use rand::{
        distributions::{Distribution, Slice},
        Rng,
    };
    use std::ops::RangeInclusive;

    fn key_simple() -> BodyHasherKey {
        (None, HashAlgorithm::Sha256, Simple)
    }

    fn limited_key_simple(n: usize) -> BodyHasherKey {
        (Some(n), HashAlgorithm::Sha256, Simple)
    }

    fn key_relaxed() -> BodyHasherKey {
        (None, HashAlgorithm::Sha256, Relaxed)
    }

    fn limited_key_relaxed(n: usize) -> BodyHasherKey {
        (Some(n), HashAlgorithm::Sha256, Relaxed)
    }

    #[test]
    fn body_hasher_simple() {
        let key1 @ (_, _, canon_alg1) = key_simple();
        let key2 @ (len, hash_alg, canon_alg2) = key_relaxed();

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        hasher.register_canonicalization(len, hash_alg, canon_alg2);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"abc \r\n"), BodyHasherStance::Interested);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(res1.as_ref().unwrap().1, 6);
        let res2 = results.get(&key2).unwrap();
        assert_eq!(res2.as_ref().unwrap().1, 5);
    }

    #[test]
    fn body_hasher_fail_on_partial() {
        let key1 @ (len, hash_alg, canon_alg1) = limited_key_relaxed(4);

        let mut hasher = BodyHasherBuilder::new(true);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"ab"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"c"), BodyHasherStance::Interested);

        // Now canonicalization adds a final CRLF, exceeding the limit 4:
        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(res1, &Err(BodyHashError::InputTruncated));
    }

    #[test]
    fn body_hasher_hash_with_length() {
        let key1 @ (len, hash_alg, canon_alg1) = limited_key_simple(28);

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"well  hello \r\n"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"\r\n what's up \r"), BodyHasherStance::Interested);
        assert_eq!(hasher.hash_chunk(b"\n\r\n"), BodyHasherStance::Done);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(
            res1.as_ref().unwrap().0,
            sha256_digest(b"well  hello \r\n\r\n what's up \r")
        );
    }

    #[test]
    fn body_hasher_known_hash_sample() {
        let key1 @ (len, hash_alg, canon_alg1) = key_relaxed();

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg, canon_alg1);
        let mut hasher = hasher.build();

        let body = b"\
Hello Proff,\r\n\
\r\n\
Let\xe2\x80\x99s try this again, with line\r\n\
breaks and empty lines even.\r\n\
\r\n\
Ciao, und bis bald\r\n\
\r\n\
\r\n\
-- \r\n\
David\r\n\
";

        assert_eq!(hasher.hash_chunk(body), BodyHasherStance::Interested);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        assert_eq!(
            util::encode_base64(&res1.as_ref().unwrap().0),
            "RMSbeRTj/zCxWeWQXpEIbiqxH0Jqg5eYs4ORzOt3MT0="
        );
    }

    #[cfg(feature = "pre-rfc8301")]
    #[test]
    fn body_hasher_reuse_canonicalized_chunk() {
        let key1 @ (len, hash_alg1, canon_alg1) = key_relaxed();
        let key2 @ (_, hash_alg2, canon_alg2) = (None, HashAlgorithm::Sha1, Relaxed);

        let mut hasher = BodyHasherBuilder::new(false);
        hasher.register_canonicalization(len, hash_alg1, canon_alg1);
        hasher.register_canonicalization(len, hash_alg2, canon_alg2);
        let mut hasher = hasher.build();

        assert_eq!(hasher.hash_chunk(b"abc \r\n"), BodyHasherStance::Interested);

        let results = hasher.finish();

        let res1 = results.get(&key1).unwrap();
        let res2 = results.get(&key2).unwrap();
        assert_eq!(res1.as_ref().unwrap().1, res2.as_ref().unwrap().1);
    }

    fn sha256_digest(msg: &[u8]) -> Box<[u8]> {
        crypto::digest(HashAlgorithm::Sha256, msg)
    }

    #[test]
    #[ignore = "randomly generated test inputs"]
    fn fuzz_body_hasher_plain() {
        fuzz_body_hasher(false);
    }

    #[test]
    #[ignore = "randomly generated test inputs"]
    fn fuzz_body_hasher_fail_on_truncate() {
        fuzz_body_hasher(true);
    }

    fn fuzz_body_hasher(fail_on_truncate: bool) {
        let elems = ["x", "y", " ", "\r\n"];
        let chunk_len = 0..=4;
        let chunk_count = 1..=4;
        let param_count = 1..=6;
        let limit = 0..=13;

        run_fuzz(1000, fail_on_truncate, &elems, chunk_len, chunk_count, param_count, limit);
    }

    fn run_fuzz(
        repetitions: usize,
        fail_on_truncate: bool,
        elems: &[&str],
        chunk_len: RangeInclusive<u8>,
        chunk_count: RangeInclusive<u8>,
        param_count: RangeInclusive<u8>,
        limit: RangeInclusive<u8>,
    ) {
        let elems = Slice::new(elems).unwrap();

        let hashes = Slice::new(&[
            HashAlgorithm::Sha256,
            #[cfg(feature = "pre-rfc8301")]
            HashAlgorithm::Sha1,
        ])
        .unwrap();

        let canons = Slice::new(&[Simple, Relaxed]).unwrap();

        let mut rng = rand::thread_rng();

        for _ in 0..repetitions {
            // generate body chunks
            let mut chunks = vec![];
            for _ in 0..rng.gen_range(chunk_count.clone()) {
                let n = rng.gen_range(chunk_len.clone()).into();
                let s: String = elems.sample_iter(&mut rng).copied().take(n).collect();
                chunks.push(s);
            }
            let chunks: Vec<_> = chunks.iter().map(|s| s.as_str()).collect();

            // generate hasher keys/params
            let mut params = vec![];
            for _ in 0..rng.gen_range(param_count.clone()) {
                let l = if rng.gen_bool(1.0 / 4.0) {
                    None
                } else {
                    Some(rng.gen_range(limit.clone()).into())
                };
                let h = hashes.sample(&mut rng);
                let c = canons.sample(&mut rng);
                params.push((l, *h, *c));
            }

            compare_impls(fail_on_truncate, &chunks, &params);
        }
    }

    fn compare_impls(fail_on_truncate: bool, chunks: &[&str], params: &[BodyHasherKey]) {
        // implementation based on BodyHasher
        let mut hasher = BodyHasherBuilder::new(fail_on_truncate);
        for &(l, h, c) in params {
            hasher.register_canonicalization(l, h, c);
        }
        let mut hasher = hasher.build();

        for ch in chunks {
            if let BodyHasherStance::Done = hasher.hash_chunk(ch.as_bytes()) {
                break;
            }
        }

        let results = hasher.finish();

        // alternative implementation
        let s: String = chunks.iter().copied().collect();
        let alt_impl = move |(l, h, c)| {
            let mut bc = BodyCanonicalizer::new(c);
            let mut result = bc.canonicalize_chunk(s.as_bytes()).into_owned();
            result.extend(bc.finish().into_owned());

            if let Some(n) = l {
                if n > result.len() {
                    return Err(BodyHashError::InsufficientInput);
                }
                if fail_on_truncate && n < result.len() {
                    return Err(BodyHashError::InputTruncated);
                }
                result.truncate(n);
            }

            let hash = crypto::digest(h, &result);

            Ok((hash, result.len()))
        };

        // compare results
        for &key in params {
            let r1 = results.get(&key).unwrap();
            let r2 = alt_impl(key);

            assert_eq!(
                r1, &r2,
                "divergent results for inputs {chunks:?} and {key:?}",
            );
        }
    }
}
