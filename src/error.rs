// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

use std::fmt;

/// Errors from locating an HTML-embedded manifest or validating its hard
/// binding.
///
/// # Multiple manifests is a reportable failure
///
/// A document shall carry at most one C2PA Manifest Store association. The
/// specification requires a validator that encounters more than one manifest
/// element to report a `manifest.html.multipleManifests` failure, so
/// [`Error::MultipleManifests`] carries that code and is *not* a
/// "no manifests located" outcome — the manifests were located, and the
/// document is rejected for carrying too many.
///
/// The other two location outcomes carry no status code. Finding nothing is
/// simply an unsigned document, and the specification names no code for an
/// element that matches but yields no Manifest Store. Only [`Error::code`]
/// speaks for the specification; [`Error::is_no_manifest_located`] draws the
/// line a caller surfacing provenance state to a user actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The `head` carries no `script` with `type="application/c2pa"` and no
    /// `link` with `rel="c2pa-manifest"`: the document simply carries no
    /// manifest.
    NotFound,
    /// More than one C2PA manifest element was found.
    ///
    /// Covers all three prohibited shapes: two `script` elements, two `link`
    /// elements, and a `script` alongside a `link`. Reported as
    /// `manifest.html.multipleManifests`.
    MultipleManifests,
    /// Exactly one manifest element was found but it could not yield a Manifest
    /// Store: a `script` whose content is not valid Base64, or a `link` with no
    /// `href`.
    ///
    /// The specification does not name this case. Treating it as "no manifests
    /// located" is the fail-safe reading: nothing was obtained, so there is
    /// nothing to validate and nothing to report a failure against.
    MalformedElement(&'static str),
    /// The document has no `head` to insert into. Embedding needs an explicit
    /// `</head>`; a document relying on HTML's implied `head` must be
    /// serialized with one first.
    NoHead,
    /// The exclusion ranges are malformed: out of order, overlapping, extending
    /// past the end of the document, or not matching the located manifest
    /// element.
    MalformedExclusion,
    /// The recomputed data hash did not match the value in the assertion.
    HashMismatch,
    /// A hash algorithm identifier outside the C2PA allowed list was requested.
    UnsupportedAlgorithm(String),
}

impl Error {
    /// The registered C2PA validation status code for this error, or `None`
    /// when the condition carries no status code.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::MultipleManifests => "manifest.html.multipleManifests",
            // Finding nothing is not a failure, and the specification names no
            // code for an element that matches but yields no Manifest Store.
            Self::NotFound | Self::MalformedElement(_) => return None,
            // An embed-time input error, not a validation outcome.
            Self::NoHead => return None,
            Self::MalformedExclusion => "assertion.dataHash.malformed",
            Self::HashMismatch => "assertion.dataHash.mismatch",
            Self::UnsupportedAlgorithm(_) => "algorithm.unsupported",
        })
    }

    /// Whether this error means the document carries no provenance at all, as
    /// opposed to provenance that was found and rejected.
    ///
    /// Note that [`Error::MultipleManifests`] is *not* one of these: the
    /// manifests were located, and the document is rejected for carrying more
    /// than one.
    pub fn is_no_manifest_located(&self) -> bool {
        matches!(self, Self::NotFound | Self::MalformedElement(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no C2PA manifest element found in the document head"),
            Self::MultipleManifests => write!(f, "more than one C2PA manifest element found"),
            Self::MalformedElement(why) => {
                write!(f, "the C2PA manifest element is malformed: {why}")
            }
            Self::NoHead => write!(f, "the document has no head element to embed into"),
            Self::MalformedExclusion => write!(f, "data hash exclusion range is malformed"),
            Self::HashMismatch => write!(f, "data hash does not match the document content"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported hash algorithm: {a}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Error> {
        vec![
            Error::NotFound,
            Error::MultipleManifests,
            Error::MalformedElement("content is not valid Base64"),
            Error::NoHead,
            Error::MalformedExclusion,
            Error::HashMismatch,
            Error::UnsupportedAlgorithm("sha1".into()),
        ]
    }

    #[test]
    fn display_composes_into_a_sentence_for_every_variant() {
        for e in all() {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} rendered empty");
            // Messages are embedded in larger sentences, so they must not start
            // with a capital or end with a period.
            assert!(!s.ends_with('.'), "{e:?} ends with a period: {s}");
            let first = s.chars().next().expect("checked non-empty above");
            assert!(!first.is_uppercase(), "{e:?} starts uppercase: {s}");
        }
    }

    #[test]
    fn display_carries_the_offending_value() {
        assert!(Error::UnsupportedAlgorithm("sha1".into())
            .to_string()
            .contains("sha1"));
        assert!(Error::MalformedElement("link has no href")
            .to_string()
            .contains("link has no href"));
    }

    #[test]
    fn multiple_manifests_is_a_reportable_failure() {
        // The specification requires the code, so a validator must be able to
        // report it. It is a rejection, not an absence of provenance.
        assert_eq!(
            Error::MultipleManifests.code(),
            Some("manifest.html.multipleManifests")
        );
        assert!(!Error::MultipleManifests.is_no_manifest_located());
    }

    #[test]
    fn every_code_is_a_registered_identifier() {
        for e in all() {
            if let Some(code) = e.code() {
                assert!(
                    matches!(
                        code,
                        "manifest.html.multipleManifests"
                            | "assertion.dataHash.malformed"
                            | "assertion.dataHash.mismatch"
                            | "algorithm.unsupported"
                    ),
                    "{e:?} reports an unregistered code: {code}"
                );
            }
        }
    }

    #[test]
    fn absence_of_provenance_carries_no_code() {
        for e in [
            Error::NotFound,
            Error::MalformedElement("content is not valid Base64"),
        ] {
            assert_eq!(e.code(), None, "{e:?} must not report a status code");
            assert!(
                e.is_no_manifest_located(),
                "{e:?} must classify as unsigned"
            );
        }
        // Identical to a validator, distinct to an integrator: "carries none"
        // versus "carried one that was mangled in transit".
        assert_ne!(Error::MalformedElement("x"), Error::NotFound);
    }

    #[test]
    fn binding_failures_are_not_no_manifest_located() {
        // A located manifest that fails its binding is "invalid", never "unsigned".
        for e in [
            Error::MalformedExclusion,
            Error::HashMismatch,
            Error::UnsupportedAlgorithm("sha1".into()),
        ] {
            assert!(!e.is_no_manifest_located(), "{e:?} misclassified");
            assert!(e.code().is_some(), "{e:?} should report a code");
        }
    }

    #[test]
    fn no_head_is_neither_a_location_outcome_nor_a_validation_failure() {
        assert_eq!(Error::NoHead.code(), None);
        assert!(!Error::NoHead.is_no_manifest_located());
    }
}
