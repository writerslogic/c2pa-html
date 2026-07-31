// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! The `c2pa.hash.data` hard binding for HTML documents.
//!
//! # Coverage
//!
//! - **Inline manifest**: one exclusion range covering the entire `script`
//!   element, `<script` through `</script>` inclusive. The hash is over the
//!   document with that range removed.
//! - **External manifest**: no exclusion range at all. The hash is over the
//!   entire document, `link` element included.
//!
//! The hash is defined over the bytes of the document *as stored*, with no
//! normalization of any kind. Anything that re-serializes the HTML — a CMS, a
//! CDN, a formatter that rewrites quote styles or collapses whitespace — shifts
//! byte offsets and invalidates the binding. That is by design: re-serialization
//! is a content modification. A generator in such a pipeline embeds after the
//! final serialization step, or uses an external manifest.
//!
//! Contrast the text bindings, which normalize: A.9 hashes raw file bytes
//! because structured text is byte-stable on disk, and A.8 normalizes to NFC
//! because clipboard-portable text may arrive in any normalization form. HTML is
//! a file, so it is bytes.
//!
//! # The inline hash can be computed before the manifest exists
//!
//! Because the exclusion covers the *entire* script element, the covered bytes
//! are the document with the element cut out — which, for an element that was
//! inserted rather than edited, is the original document. So a generator does
//! not need the placeholder-reserve-then-fill dance other formats require: hash
//! the document, sign, then embed. [`inline_hash_before_embed`] is that
//! shortcut, and [`compute_data_hash`] on the embedded result agrees with it.
//!
//! An external manifest has no exclusion, so the `link` element is inside the
//! hash and the order is reversed: insert the `link` first, then hash.
//!
//! # Dependency-free
//!
//! [`Sha2`] implements all three C2PA digest algorithms in-crate, so the binding
//! works out of the box with nothing pulled in. Hashing still goes through the
//! [`Hasher`] trait, so a caller with a reason to substitute — an accelerated or
//! hardware-backed digest, or one already provided by the host runtime — passes
//! their own instead.

use crate::base64;
use crate::document::{self, Manifest};
use crate::error::Error;

/// The assertion label for the hard binding.
pub const DATA_HASH_LABEL: &str = "c2pa.hash.data";

/// A byte range excluded from the data hash, matching the `EXCLUSION_RANGE-map`
/// CDDL (`start`, `length`). Offsets are into the document as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exclusion {
    pub start: usize,
    pub length: usize,
}

impl Exclusion {
    fn end(&self) -> Option<usize> {
        self.start.checked_add(self.length)
    }
}

/// A C2PA-allowed hash algorithm for the data hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// The C2PA algorithm identifier used in the `alg` field.
    pub fn id(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    pub fn from_id(id: &str) -> Result<Self, Error> {
        match id {
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            other => Err(Error::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// A digest implementation. [`Sha2`] is the built-in one; the trait exists so a
/// caller can substitute an accelerated or host-provided digest without the
/// binding algorithm depending on either.
pub trait Hasher {
    fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8>;
}

/// The built-in [`Hasher`]: SHA-256, SHA-384, and SHA-512 per FIPS 180-4,
/// implemented in-crate so the binding pulls in no dependency.
///
/// It is portable and correct but not vectorized. For a large asset, inject an
/// accelerated implementation instead — that is what the trait is for.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha2;

impl Hasher for Sha2 {
    fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8> {
        match alg {
            Algorithm::Sha256 => crate::sha2::sha256(data),
            Algorithm::Sha384 => crate::sha2::sha384(data),
            Algorithm::Sha512 => crate::sha2::sha512(data),
        }
    }
}

/// A computed `c2pa.hash.data` assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHash {
    pub exclusions: Vec<Exclusion>,
    pub alg: String,
    pub hash: Vec<u8>,
    pub name: Option<String>,
}

impl DataHash {
    /// The assertion label, `c2pa.hash.data`.
    pub fn label(&self) -> &'static str {
        DATA_HASH_LABEL
    }

    /// Serialise to the JSON shape consumed when building a manifest, with the
    /// hash as standard Base64. Hand-built to keep the crate dependency-free;
    /// the field set matches the `data-hash-map` CDDL.
    pub fn to_json(&self) -> String {
        let ranges: Vec<String> = self
            .exclusions
            .iter()
            .map(|e| format!("{{\"start\":{},\"length\":{}}}", e.start, e.length))
            .collect();
        let mut json = format!(
            "{{\"exclusions\":[{}],\"alg\":\"{}\",\"hash\":\"{}\"",
            ranges.join(","),
            self.alg,
            base64::encode(&self.hash)
        );
        if let Some(name) = &self.name {
            json.push_str(&format!(",\"name\":\"{name}\""));
        }
        json.push('}');
        json
    }
}

/// The exclusion ranges for the document's manifest association.
///
/// One range covering the whole `script` element for an inline manifest; none
/// at all for an external one.
pub fn manifest_exclusions(html: &[u8]) -> Result<Vec<Exclusion>, Error> {
    match document::extract(html)? {
        Manifest::Embedded { start, length, .. } => Ok(vec![Exclusion { start, length }]),
        Manifest::Referenced { .. } => Ok(Vec::new()),
    }
}

/// Remove `exclusions` from `html`, validating that they are ordered,
/// non-overlapping, and within bounds.
pub fn apply_exclusions(html: &[u8], exclusions: &[Exclusion]) -> Result<Vec<u8>, Error> {
    let mut cursor = 0usize;
    let mut out = Vec::with_capacity(html.len());
    for ex in exclusions {
        let end = ex.end().ok_or(Error::MalformedExclusion)?;
        if ex.start < cursor || end > html.len() {
            return Err(Error::MalformedExclusion);
        }
        out.extend_from_slice(&html[cursor..ex.start]);
        cursor = end;
    }
    out.extend_from_slice(&html[cursor..]);
    Ok(out)
}

/// Compute the hard binding for `html`: locate the manifest element, exclude it
/// if it is inline, and hash what the exclusions leave.
pub fn compute_data_hash(
    html: &[u8],
    alg: Algorithm,
    hasher: &impl Hasher,
) -> Result<DataHash, Error> {
    let exclusions = manifest_exclusions(html)?;
    let covered = apply_exclusions(html, &exclusions)?;
    Ok(DataHash {
        exclusions,
        alg: alg.id().to_string(),
        hash: hasher.digest(alg, &covered),
        name: None,
    })
}

/// The hash an inline binding will have once a `script` element is embedded in
/// `html`, computed before the manifest exists.
///
/// The exclusion covers the whole element, so the covered bytes are the
/// document without it — this document. Pair the result with the exclusion
/// [`compute_data_hash`] reports after embedding; the two agree.
///
/// This is the ordering that makes an inline HTML manifest signable: hash,
/// sign, embed. There is no equivalent for an external manifest, whose `link`
/// element is inside the hash.
pub fn inline_hash_before_embed(html: &[u8], alg: Algorithm, hasher: &impl Hasher) -> Vec<u8> {
    hasher.digest(alg, html)
}

/// Verify a `c2pa.hash.data` binding against `html`, following the validator
/// procedure: apply the assertion's own exclusion ranges, recompute, compare.
///
/// The ranges must match the located manifest element. An assertion that
/// excludes some other span would otherwise hash a document the manifest does
/// not describe.
pub fn verify_data_hash(
    html: &[u8],
    data_hash: &DataHash,
    hasher: &impl Hasher,
) -> Result<(), Error> {
    let alg = Algorithm::from_id(&data_hash.alg)?;
    let located = manifest_exclusions(html)?;
    // An inline manifest must be excluded; an external one must not be, since
    // the `link` element is part of what the hash covers.
    let ranges_agree = match located.first() {
        Some(l) => data_hash.exclusions.contains(l),
        None => data_hash.exclusions.is_empty(),
    };
    if !ranges_agree {
        return Err(Error::MalformedExclusion);
    }
    let covered = apply_exclusions(html, &data_hash.exclusions)?;
    if hasher.digest(alg, &covered) == data_hash.hash {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::tests::DOC;

    const STORE: &[u8] = b"manifest-store-bytes";
    const HREF: &str = "https://a.example/m.c2pa";

    /// A deterministic stand-in so the core is testable without the feature.
    struct SumHasher;
    impl Hasher for SumHasher {
        fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8> {
            let n: u64 = data.iter().map(|&b| b as u64).sum();
            let mut v = alg.id().as_bytes().to_vec();
            v.extend_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&(data.len() as u64).to_be_bytes());
            v
        }
    }

    #[test]
    fn an_inline_exclusion_covers_the_whole_script_element() {
        let html = document::embed(DOC, STORE).unwrap();
        let ex = manifest_exclusions(&html).unwrap();
        assert_eq!(ex.len(), 1);
        let element = &html[ex[0].start..ex[0].start + ex[0].length];
        assert!(element.starts_with(b"<script"));
        assert!(element.ends_with(b"</script>"));
    }

    #[test]
    fn an_external_manifest_has_no_exclusion() {
        let html = document::embed_reference(DOC, HREF).unwrap();
        assert_eq!(manifest_exclusions(&html).unwrap(), Vec::new());
    }

    #[test]
    fn the_covered_bytes_of_an_inline_embed_are_the_original_document() {
        let html = document::embed(DOC, STORE).unwrap();
        let ex = manifest_exclusions(&html).unwrap();
        // `embed` adds no bytes outside the element and the exclusion covers the
        // whole element, so cutting it out leaves the document untouched.
        assert_eq!(apply_exclusions(&html, &ex).unwrap(), DOC);
    }

    #[test]
    fn the_covered_bytes_of_an_external_embed_include_the_link() {
        let html = document::embed_reference(DOC, HREF).unwrap();
        let covered = apply_exclusions(&html, &[]).unwrap();
        assert_eq!(covered, html);
        assert!(covered.windows(HREF.len()).any(|w| w == HREF.as_bytes()));
    }

    #[test]
    fn compute_then_verify_round_trips_inline() {
        let html = document::embed(DOC, STORE).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        assert_eq!(dh.alg, "sha256");
        assert_eq!(dh.label(), "c2pa.hash.data");
        assert!(verify_data_hash(&html, &dh, &SumHasher).is_ok());
    }

    #[test]
    fn compute_then_verify_round_trips_external() {
        let html = document::embed_reference(DOC, HREF).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        assert!(dh.exclusions.is_empty());
        assert!(verify_data_hash(&html, &dh, &SumHasher).is_ok());
    }

    #[test]
    fn the_manifest_content_does_not_affect_an_inline_hash() {
        // The exclusion covers the whole element, so two documents differing
        // only in the store bind identically — as long as the Base64 is the same
        // length, which it is for a fixed store size.
        let a = document::embed(DOC, b"aaaaaaaa").unwrap();
        let b = document::embed(DOC, b"bbbbbbbb").unwrap();
        let ha = compute_data_hash(&a, Algorithm::Sha256, &SumHasher).unwrap();
        let hb = compute_data_hash(&b, Algorithm::Sha256, &SumHasher).unwrap();
        assert_eq!(ha.hash, hb.hash);
        assert_eq!(ha.exclusions, hb.exclusions);
    }

    #[test]
    fn the_hash_can_be_computed_before_the_manifest_exists() {
        let before = inline_hash_before_embed(DOC, Algorithm::Sha256, &SumHasher);
        let html = document::embed(DOC, STORE).unwrap();
        let after = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        assert_eq!(
            before, after.hash,
            "hash-then-embed must agree with embed-then-hash"
        );
        // And the assertion built that way verifies against the embedded document.
        let dh = DataHash {
            exclusions: after.exclusions.clone(),
            alg: Algorithm::Sha256.id().to_string(),
            hash: before,
            name: None,
        };
        assert!(verify_data_hash(&html, &dh, &SumHasher).is_ok());
    }

    #[test]
    fn editing_the_document_breaks_an_inline_binding() {
        let html = document::embed(DOC, STORE).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        // Same length, so the exclusion still matches and the hash is what fails.
        let tampered = document::embed(
            &String::from_utf8(DOC.to_vec())
                .unwrap()
                .replace("Content here.", "Content harel")
                .into_bytes(),
            STORE,
        )
        .unwrap();
        assert_eq!(
            verify_data_hash(&tampered, &dh, &SumHasher),
            Err(Error::HashMismatch)
        );
    }

    #[test]
    fn editing_the_document_breaks_an_external_binding() {
        let html = document::embed_reference(DOC, HREF).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        let tampered = document::embed_reference(
            &String::from_utf8(DOC.to_vec())
                .unwrap()
                .replace("Content here.", "Content harel")
                .into_bytes(),
            HREF,
        )
        .unwrap();
        assert_eq!(
            verify_data_hash(&tampered, &dh, &SumHasher),
            Err(Error::HashMismatch)
        );
    }

    #[test]
    fn repointing_an_external_reference_breaks_its_binding() {
        // The `link` is inside the hash precisely so the URI cannot be swapped.
        let html = document::embed_reference(DOC, HREF).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        let repointed = document::embed_reference(DOC, "https://b.example/m.c2pa").unwrap();
        assert_eq!(
            verify_data_hash(&repointed, &dh, &SumHasher),
            Err(Error::HashMismatch)
        );
    }

    #[test]
    fn an_exclusion_that_is_not_the_element_is_rejected() {
        let html = document::embed(DOC, STORE).unwrap();
        let mut dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        dh.exclusions = vec![Exclusion {
            start: 0,
            length: 4,
        }];
        assert_eq!(
            verify_data_hash(&html, &dh, &SumHasher),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn an_inline_binding_with_no_exclusion_is_rejected() {
        let html = document::embed(DOC, STORE).unwrap();
        let mut dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        dh.exclusions.clear();
        assert_eq!(
            verify_data_hash(&html, &dh, &SumHasher),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn an_external_binding_that_excludes_its_link_is_rejected() {
        // Excluding the `link` would let the URI be swapped freely.
        let html = document::embed_reference(DOC, HREF).unwrap();
        let mut dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        let range = document::extract(&html).unwrap().range();
        dh.exclusions = vec![Exclusion {
            start: range.start,
            length: range.len(),
        }];
        assert_eq!(
            verify_data_hash(&html, &dh, &SumHasher),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn malformed_ranges_are_rejected() {
        let html = document::embed(DOC, STORE).unwrap();
        // Out of order / overlapping.
        let bad = [
            Exclusion {
                start: 10,
                length: 5,
            },
            Exclusion {
                start: 5,
                length: 5,
            },
        ];
        assert_eq!(
            apply_exclusions(&html, &bad),
            Err(Error::MalformedExclusion)
        );
        // Past the end.
        assert_eq!(
            apply_exclusions(
                &html,
                &[Exclusion {
                    start: 0,
                    length: html.len() + 1
                }]
            ),
            Err(Error::MalformedExclusion)
        );
        // Overflowing.
        assert_eq!(
            apply_exclusions(
                &html,
                &[Exclusion {
                    start: usize::MAX,
                    length: 1
                }]
            ),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn unsupported_algorithm_is_reported() {
        let html = document::embed(DOC, STORE).unwrap();
        let mut dh = compute_data_hash(&html, Algorithm::Sha256, &SumHasher).unwrap();
        dh.alg = "sha1".into();
        assert_eq!(
            verify_data_hash(&html, &dh, &SumHasher),
            Err(Error::UnsupportedAlgorithm("sha1".into()))
        );
    }

    #[test]
    fn binding_a_document_with_no_manifest_reports_not_found() {
        assert_eq!(
            compute_data_hash(DOC, Algorithm::Sha256, &SumHasher),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn algorithm_ids_round_trip() {
        for alg in [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512] {
            assert_eq!(Algorithm::from_id(alg.id()), Ok(alg));
        }
        assert_eq!(
            Algorithm::from_id("md5"),
            Err(Error::UnsupportedAlgorithm("md5".into()))
        );
    }

    #[test]
    fn json_shape_matches_the_data_hash_map() {
        let dh = DataHash {
            exclusions: vec![Exclusion {
                start: 73,
                length: 114,
            }],
            alg: "sha256".into(),
            hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
            name: None,
        };
        assert_eq!(
            dh.to_json(),
            r#"{"exclusions":[{"start":73,"length":114}],"alg":"sha256","hash":"3q2+7w=="}"#
        );
    }

    #[test]
    fn json_omits_exclusions_for_an_external_manifest() {
        let dh = DataHash {
            exclusions: Vec::new(),
            alg: "sha512".into(),
            hash: vec![0x01],
            name: Some("html".into()),
        };
        assert_eq!(
            dh.to_json(),
            r#"{"exclusions":[],"alg":"sha512","hash":"AQ==","name":"html"}"#
        );
    }

    #[test]
    fn the_built_in_hasher_dispatches_to_the_right_algorithm() {
        // FIPS 180-4 vector for the empty string, so a mis-wired match arm shows
        // up here rather than as a silent interop failure.
        assert_eq!(
            Sha2.digest(Algorithm::Sha256, b"")[..4],
            [0xE3, 0xB0, 0xC4, 0x42]
        );
        assert_eq!(
            Sha2.digest(Algorithm::Sha384, b"")[..4],
            [0x38, 0xB0, 0x60, 0xA7]
        );
        assert_eq!(
            Sha2.digest(Algorithm::Sha512, b"")[..4],
            [0xCF, 0x83, 0xE1, 0x35]
        );
        assert_eq!(Sha2.digest(Algorithm::Sha256, b"").len(), 32);
        assert_eq!(Sha2.digest(Algorithm::Sha384, b"").len(), 48);
        assert_eq!(Sha2.digest(Algorithm::Sha512, b"").len(), 64);
    }

    #[test]
    fn the_built_in_hasher_round_trips_a_real_binding() {
        for alg in [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512] {
            let html = document::embed(DOC, STORE).unwrap();
            let dh = compute_data_hash(&html, alg, &Sha2).unwrap();
            assert!(verify_data_hash(&html, &dh, &Sha2).is_ok(), "{alg:?}");

            let referenced = document::embed_reference(DOC, HREF).unwrap();
            let dh = compute_data_hash(&referenced, alg, &Sha2).unwrap();
            assert!(verify_data_hash(&referenced, &dh, &Sha2).is_ok(), "{alg:?}");
        }
    }

    #[test]
    fn the_built_in_hasher_detects_tampering() {
        let html = document::embed(DOC, STORE).unwrap();
        let dh = compute_data_hash(&html, Algorithm::Sha256, &Sha2).unwrap();
        let tampered = document::embed(
            &String::from_utf8(DOC.to_vec())
                .unwrap()
                .replace("Content here.", "Content harel")
                .into_bytes(),
            STORE,
        )
        .unwrap();
        assert_eq!(
            verify_data_hash(&tampered, &dh, &Sha2),
            Err(Error::HashMismatch)
        );
    }
}
