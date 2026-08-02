//! End-to-end use of the public API, as a consumer sees it.
//!
//! The unit tests reach into private modules; these exercise only what is
//! exported, which is what catches an accidental change to the public surface.

use c2pa_html::hardbinding::{
    compute_data_hash, inline_hash_before_embed, verify_data_hash, Algorithm, DataHash, Exclusion,
    Sha2,
};
use c2pa_html::{document, Error};

const PAGE: &[u8] = b"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <title>Example</title>\n</head>\n<body>\n    <p>Content.</p>\n</body>\n</html>\n";
const STORE: &[u8] = b"\x00\x01\x02manifest-store\xFF";

#[test]
fn inline_embed_extract_bind_and_remove() {
    let embedded = document::embed(PAGE, STORE).unwrap();
    assert_eq!(document::extract(&embedded).unwrap().store(), Some(STORE));

    let binding = compute_data_hash(&embedded, Algorithm::Sha256, &Sha2).unwrap();
    assert_eq!(binding.exclusions.len(), 1);
    assert!(verify_data_hash(&embedded, &binding, &Sha2).is_ok());

    assert_eq!(document::remove(&embedded).unwrap(), PAGE);
}

#[test]
fn external_reference_round_trips_and_binds_without_exclusions() {
    let uri = "https://fabrikam.example/m.c2pa";
    let referenced = document::embed_reference(PAGE, uri).unwrap();
    assert_eq!(document::extract(&referenced).unwrap().href(), Some(uri));

    let binding = compute_data_hash(&referenced, Algorithm::Sha256, &Sha2).unwrap();
    assert!(
        binding.exclusions.is_empty(),
        "an external manifest excludes nothing, so the link cannot be swapped"
    );
    assert!(verify_data_hash(&referenced, &binding, &Sha2).is_ok());
}

#[test]
fn the_hash_can_be_computed_before_the_manifest_exists() {
    // The generator flow: hash, sign, embed — no reserve-then-fill needed.
    let before = inline_hash_before_embed(PAGE, Algorithm::Sha256, &Sha2);
    let embedded = document::embed(PAGE, STORE).unwrap();
    let after = compute_data_hash(&embedded, Algorithm::Sha256, &Sha2).unwrap();
    assert_eq!(before, after.hash);

    let assertion = DataHash {
        exclusions: after.exclusions.clone(),
        alg: Algorithm::Sha256.id().to_string(),
        hash: before,
        name: None,
    };
    assert!(verify_data_hash(&embedded, &assertion, &Sha2).is_ok());
}

#[test]
fn editing_the_document_breaks_the_binding() {
    let embedded = document::embed(PAGE, STORE).unwrap();
    let binding = compute_data_hash(&embedded, Algorithm::Sha256, &Sha2).unwrap();

    // Same length, so the exclusion still matches and only the hash differs.
    let tampered = document::embed(
        &String::from_utf8(PAGE.to_vec())
            .unwrap()
            .replace("Content.", "Contenx.")
            .into_bytes(),
        STORE,
    )
    .unwrap();
    assert_eq!(
        verify_data_hash(&tampered, &binding, &Sha2),
        Err(Error::HashMismatch)
    );
}

#[test]
fn two_manifests_are_the_specified_failure() {
    let html = b"<head><script type=\"application/c2pa\">aGk=</script><link rel=\"c2pa-manifest\" href=\"m\"></head>";
    let err = document::extract(html).unwrap_err();
    assert_eq!(err, Error::MultipleManifests);
    assert_eq!(err.code(), Some("manifest.html.multipleManifests"));
    assert!(!err.is_no_manifest_located());
    assert_eq!(document::locate_all(html).len(), 2);
}

#[test]
fn a_document_without_provenance_is_unsigned_not_failed() {
    let err = document::extract(PAGE).unwrap_err();
    assert_eq!(err, Error::NotFound);
    assert_eq!(err.code(), None);
    assert!(err.is_no_manifest_located());
}

#[test]
fn an_assertion_naming_the_wrong_span_is_rejected() {
    let embedded = document::embed(PAGE, STORE).unwrap();
    let bogus = DataHash {
        exclusions: vec![Exclusion {
            start: 0,
            length: 4,
        }],
        alg: "sha256".into(),
        hash: vec![0; 32],
        name: None,
    };
    assert_eq!(
        verify_data_hash(&embedded, &bogus, &Sha2),
        Err(Error::MalformedExclusion)
    );
}

#[test]
fn every_allowed_algorithm_round_trips() {
    let embedded = document::embed(PAGE, STORE).unwrap();
    for (alg, len) in [
        (Algorithm::Sha256, 32),
        (Algorithm::Sha384, 48),
        (Algorithm::Sha512, 64),
    ] {
        let binding = compute_data_hash(&embedded, alg, &Sha2).unwrap();
        assert_eq!(binding.hash.len(), len, "{alg:?}");
        assert!(
            verify_data_hash(&embedded, &binding, &Sha2).is_ok(),
            "{alg:?}"
        );
    }
}
