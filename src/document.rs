// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! Discovering, embedding, and removing a C2PA manifest association in an HTML
//! document.
//!
//! Two associations are specified, both scoped to the document `head`:
//!
//! - an **inline** manifest, the Base64 content of a
//!   `<script type="application/c2pa">` element, and
//! - an **external** manifest, referenced by a
//!   `<link rel="c2pa-manifest" href="…">` element.
//!
//! The specification prefers the external form. A document shall carry at most
//! one association: two `script` elements, two `link` elements, or one of each
//! all mean the document is treated as if no manifests were located.

use crate::base64;
use crate::error::Error;
use crate::scan::{self, Tag};
use std::ops::Range;

/// The `script` type that marks an inline Manifest Store.
pub const SCRIPT_TYPE: &str = "application/c2pa";

/// The IANA-registered link relation that marks an external Manifest Store.
pub const LINK_REL: &str = "c2pa-manifest";

/// A located C2PA manifest association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    /// An inline Manifest Store carried by a `script` element. `start` and
    /// `length` cover the whole element, `<script` through `</script>`
    /// inclusive — the exact span the hard binding excludes.
    Embedded {
        start: usize,
        length: usize,
        store: Vec<u8>,
    },
    /// A reference to an external Manifest Store carried by a `link` element.
    /// `start` and `length` cover the whole element, which the hard binding
    /// does *not* exclude.
    Referenced {
        start: usize,
        length: usize,
        href: String,
    },
}

impl Manifest {
    /// Byte offset of the element's opening `<`.
    pub fn start(&self) -> usize {
        match self {
            Self::Embedded { start, .. } | Self::Referenced { start, .. } => *start,
        }
    }

    /// Byte length of the whole element.
    pub fn length(&self) -> usize {
        match self {
            Self::Embedded { length, .. } | Self::Referenced { length, .. } => *length,
        }
    }

    /// The element's byte range in the document.
    pub fn range(&self) -> Range<usize> {
        self.start()..self.start() + self.length()
    }

    /// The decoded Manifest Store, for an inline manifest.
    pub fn store(&self) -> Option<&[u8]> {
        match self {
            Self::Embedded { store, .. } => Some(store),
            Self::Referenced { .. } => None,
        }
    }

    /// The URI of the external Manifest Store, for a referenced manifest.
    pub fn href(&self) -> Option<&str> {
        match self {
            Self::Referenced { href, .. } => Some(href),
            Self::Embedded { .. } => None,
        }
    }
}

/// A manifest element found during discovery, before its content is decoded.
///
/// Multiplicity is decided on matching *elements*, not on whether they yield a
/// Manifest Store, so candidates are counted before anything is decoded.
struct Candidate {
    range: Range<usize>,
    kind: CandidateKind,
}

enum CandidateKind {
    /// The byte range of the `script` element's text content.
    Script(Range<usize>),
    Link(Option<String>),
}

fn is_script(tag: &Tag) -> bool {
    !tag.is_end && tag.name == "script" && tag.attr_is("type", SCRIPT_TYPE)
}

fn is_link(tag: &Tag) -> bool {
    // The `type` attribute should be present but is not required for discovery;
    // the validator matches on `rel` alone.
    !tag.is_end && tag.name == "link" && tag.attr_has_token("rel", LINK_REL)
}

/// Every C2PA manifest element in the document head, in source order.
fn candidates(html: &[u8]) -> Vec<Candidate> {
    let tags = scan::tags(html);
    let head = scan::head(html, &tags);
    let mut out = Vec::new();

    for (i, tag) in tags.iter().enumerate() {
        if tag.start < head.content.start || tag.end > head.content.end {
            continue;
        }
        if is_link(tag) {
            out.push(Candidate {
                range: tag.start..tag.end,
                kind: CandidateKind::Link(tag.attr("href").map(str::to_string)),
            });
        } else if is_script(tag) {
            // The scanner emits a raw-text element's end tag as the very next
            // tag, so the element ends there. Without one the element runs to
            // the end of the document, as a browser would treat it.
            let close = tags
                .get(i + 1)
                .filter(|t| t.is_end && t.name == "script")
                .map(|t| (t.start, t.end))
                .unwrap_or((html.len(), html.len()));
            out.push(Candidate {
                range: tag.start..close.1,
                kind: CandidateKind::Script(tag.end..close.0),
            });
        }
    }
    out
}

/// The byte ranges of every C2PA manifest element in the document head.
///
/// Zero means the document carries no manifest; more than one means it is
/// treated as if no manifests were located. Exposed for diagnostics — a caller
/// reporting *why* a document has no provenance wants to say "it has three".
pub fn locate_all(html: &[u8]) -> Vec<Range<usize>> {
    candidates(html).into_iter().map(|c| c.range).collect()
}

/// Locate the document's single C2PA manifest association and decode it.
///
/// Fails with [`Error::NotFound`] when there is none, [`Error::MultipleManifests`]
/// when there is more than one, and [`Error::MalformedElement`] when the one
/// element present yields no Manifest Store. All three mean "no manifests
/// located" to a validator; see [`Error::is_no_manifest_located`].
pub fn extract(html: &[u8]) -> Result<Manifest, Error> {
    let mut found = candidates(html);
    match found.len() {
        0 => return Err(Error::NotFound),
        1 => {}
        _ => return Err(Error::MultipleManifests),
    }
    let c = found.pop().expect("length checked above");
    let (start, length) = (c.range.start, c.range.len());
    match c.kind {
        CandidateKind::Script(content) => {
            // The validator strips leading and trailing whitespace from the
            // element's text content before Base64 decoding.
            let text = scan::trim(&html[content]);
            let store = base64::decode(text).ok_or(Error::MalformedElement(
                "script content is not valid Base64",
            ))?;
            Ok(Manifest::Embedded {
                start,
                length,
                store,
            })
        }
        CandidateKind::Link(href) => {
            let href = href
                .filter(|h| !h.is_empty())
                .ok_or(Error::MalformedElement("link has no href to resolve"))?;
            Ok(Manifest::Referenced {
                start,
                length,
                href,
            })
        }
    }
}

/// Splice `element` into the head, immediately before the closing `</head>`.
///
/// The element is inserted and nothing else: no newline, no indentation. Every
/// added byte lies *inside* the element, which is what makes an inline
/// binding's covered bytes exactly the original document — see
/// [`crate::hardbinding::inline_hash_before_embed`]. Adding so much as a
/// newline outside the element would put a byte in the hash that the original
/// document did not have.
///
/// The element therefore lands at whatever indentation the `</head>` line
/// already carries, so the output stays readable without costing that property.
fn insert(html: &[u8], element: &str) -> Result<Vec<u8>, Error> {
    let tags = scan::tags(html);
    let at = scan::head(html, &tags).end_tag.ok_or(Error::NoHead)?;

    let mut out = Vec::with_capacity(html.len() + element.len());
    out.extend_from_slice(&html[..at]);
    out.extend_from_slice(element.as_bytes());
    out.extend_from_slice(&html[at..]);
    Ok(out)
}

/// Embed a Manifest Store inline, as a `script` element in the document head.
///
/// Any existing C2PA manifest elements are removed first, so embedding twice
/// replaces rather than accumulates. Fails with [`Error::NoHead`] if the
/// document has no `</head>`.
///
/// The specification prefers [`embed_reference`]; use this when the manifest
/// must travel with the document.
pub fn embed(html: &[u8], store: &[u8]) -> Result<Vec<u8>, Error> {
    let cleaned = remove(html)?;
    let element = format!(
        "<script type=\"{SCRIPT_TYPE}\">{}</script>",
        base64::encode(store)
    );
    insert(&cleaned, &element)
}

/// Reference an external Manifest Store, as a `link` element in the document
/// head.
///
/// Any existing C2PA manifest elements are removed first. Fails with
/// [`Error::NoHead`] if the document has no `</head>`.
///
/// `href` is written into an attribute verbatim except for `&`, `<`, and `"`,
/// which are escaped. A URI containing those characters is unusual but a
/// document that carries one must still parse.
pub fn embed_reference(html: &[u8], href: &str) -> Result<Vec<u8>, Error> {
    let cleaned = remove(html)?;
    let element = format!(
        "<link rel=\"{LINK_REL}\" href=\"{}\" type=\"{SCRIPT_TYPE}\">",
        escape_attribute(href)
    );
    insert(&cleaned, &element)
}

fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Remove every C2PA manifest element from the document.
///
/// A document that carries none is returned unchanged: removing nothing is not
/// an error. [`embed`] adds no bytes outside the element, so removal is its
/// exact inverse: `remove(embed(d, s)) == d`.
pub fn remove(html: &[u8]) -> Result<Vec<u8>, Error> {
    let ranges = locate_all(html);
    if ranges.is_empty() {
        return Ok(html.to_vec());
    }
    let mut out = Vec::with_capacity(html.len());
    let mut cursor = 0usize;
    for range in ranges {
        out.extend_from_slice(&html[cursor..range.start]);
        cursor = range.end;
    }
    out.extend_from_slice(&html[cursor..]);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const DOC: &[u8] = b"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <title>Example</title>\n</head>\n<body>\n    <p>Content here.</p>\n</body>\n</html>\n";

    const STORE: &[u8] = b"\x00\x01\x02manifest-store\xFF";

    fn utf8(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("output stays UTF-8")
    }

    #[test]
    fn embed_then_extract_round_trips() {
        let out = embed(DOC, STORE).unwrap();
        assert_eq!(extract(&out).unwrap().store(), Some(STORE));
    }

    #[test]
    fn embed_places_the_script_in_the_head_just_before_the_closing_tag() {
        let out = utf8(&embed(DOC, b"hi").unwrap());
        assert!(
            out.contains("<script type=\"application/c2pa\">aGk=</script></head>"),
            "{out}"
        );
        // Body content is untouched.
        assert!(out.contains("<p>Content here.</p>"));
    }

    #[test]
    fn embed_adds_no_bytes_outside_the_element() {
        // The inline hard binding excludes exactly the element, so any byte
        // added outside it would silently enter the hash.
        let out = embed(DOC, b"hi").unwrap();
        let m = extract(&out).unwrap();
        let mut without = out[..m.start()].to_vec();
        without.extend_from_slice(&out[m.start() + m.length()..]);
        assert_eq!(without, DOC);
    }

    #[test]
    fn remove_is_the_exact_inverse_of_embed() {
        assert_eq!(remove(&embed(DOC, STORE).unwrap()).unwrap(), DOC);
        assert_eq!(
            remove(&embed_reference(DOC, "https://a.example/m.c2pa").unwrap()).unwrap(),
            DOC
        );
    }

    #[test]
    fn remove_on_a_document_without_a_manifest_changes_nothing() {
        assert_eq!(remove(DOC).unwrap(), DOC);
    }

    #[test]
    fn embedding_twice_replaces_rather_than_accumulates() {
        let once = embed(DOC, b"first").unwrap();
        let twice = embed(&once, b"second").unwrap();
        assert_eq!(locate_all(&twice).len(), 1);
        assert_eq!(extract(&twice).unwrap().store(), Some(&b"second"[..]));
    }

    #[test]
    fn embedding_a_reference_replaces_an_inline_manifest() {
        let inline = embed(DOC, STORE).unwrap();
        let referenced = embed_reference(&inline, "https://a.example/m.c2pa").unwrap();
        assert_eq!(locate_all(&referenced).len(), 1);
        assert_eq!(
            extract(&referenced).unwrap().href(),
            Some("https://a.example/m.c2pa")
        );
    }

    #[test]
    fn embed_reference_writes_a_discoverable_link() {
        let out = utf8(&embed_reference(DOC, "https://a.example/m.c2pa").unwrap());
        assert!(
            out.contains(
                "<link rel=\"c2pa-manifest\" href=\"https://a.example/m.c2pa\" type=\"application/c2pa\">"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_reference_href_is_attribute_escaped() {
        let out = embed_reference(DOC, "https://a.example/m?x=1&y=\"2\"").unwrap();
        assert_eq!(
            extract(&out).unwrap().href(),
            // The parser returns the raw attribute value; entity expansion is the
            // consumer's job, and the escaping is what keeps the tag well-formed.
            Some("https://a.example/m?x=1&amp;y=&quot;2&quot;")
        );
    }

    #[test]
    fn range_covers_the_whole_element() {
        let out = embed(DOC, b"hi").unwrap();
        let m = extract(&out).unwrap();
        let element = &out[m.range()];
        assert!(element.starts_with(b"<script"));
        assert!(element.ends_with(b"</script>"));
    }

    #[test]
    fn a_document_with_no_head_cannot_be_embedded_into() {
        assert_eq!(embed(b"<p>bare</p>", b"x"), Err(Error::NoHead));
        assert_eq!(embed_reference(b"<p>bare</p>", "u"), Err(Error::NoHead));
    }

    #[test]
    fn a_document_without_a_manifest_is_not_found() {
        assert_eq!(extract(DOC), Err(Error::NotFound));
    }

    #[test]
    fn two_scripts_are_treated_as_no_manifest_located() {
        let html = b"<head><script type=\"application/c2pa\">aGk=</script><script type=\"application/c2pa\">aGk=</script></head>";
        assert_eq!(locate_all(html).len(), 2);
        assert_eq!(extract(html), Err(Error::MultipleManifests));
    }

    #[test]
    fn two_links_are_treated_as_no_manifest_located() {
        let html = b"<head><link rel=c2pa-manifest href=a><link rel=c2pa-manifest href=b></head>";
        assert_eq!(extract(html), Err(Error::MultipleManifests));
    }

    #[test]
    fn a_script_alongside_a_link_is_treated_as_no_manifest_located() {
        let html =
            b"<head><link rel=c2pa-manifest href=a><script type=application/c2pa>aGk=</script></head>";
        assert_eq!(extract(html), Err(Error::MultipleManifests));
    }

    #[test]
    fn discovery_accepts_all_three_attribute_quoting_forms() {
        for head in [
            &b"<script type=\"application/c2pa\">aGk=</script>"[..],
            &b"<script type='application/c2pa'>aGk=</script>"[..],
            &b"<script type=application/c2pa>aGk=</script>"[..],
        ] {
            let mut html = b"<head>".to_vec();
            html.extend_from_slice(head);
            html.extend_from_slice(b"</head>");
            assert_eq!(
                extract(&html).unwrap().store(),
                Some(&b"hi"[..]),
                "{}",
                utf8(head)
            );
        }
        for head in [
            &b"<link rel=\"c2pa-manifest\" href=\"m.c2pa\">"[..],
            &b"<link rel='c2pa-manifest' href='m.c2pa'>"[..],
            &b"<link rel=c2pa-manifest href=m.c2pa>"[..],
        ] {
            let mut html = b"<head>".to_vec();
            html.extend_from_slice(head);
            html.extend_from_slice(b"</head>");
            assert_eq!(
                extract(&html).unwrap().href(),
                Some("m.c2pa"),
                "{}",
                utf8(head)
            );
        }
    }

    #[test]
    fn a_link_is_discovered_on_rel_alone_without_a_type() {
        let html = b"<head><link rel=c2pa-manifest href=m.c2pa></head>";
        assert_eq!(extract(html).unwrap().href(), Some("m.c2pa"));
    }

    #[test]
    fn discovery_is_scoped_to_the_head() {
        // Identical elements in the body are not an association, so neither the
        // count nor the outcome changes.
        let html = b"<html><head><meta></head><body><script type=application/c2pa>aGk=</script><link rel=c2pa-manifest href=a></body></html>";
        assert_eq!(locate_all(html), Vec::<Range<usize>>::new());
        assert_eq!(extract(html), Err(Error::NotFound));
    }

    #[test]
    fn a_body_element_does_not_make_a_head_element_ambiguous() {
        let html = b"<html><head><link rel=c2pa-manifest href=good></head><body><link rel=c2pa-manifest href=ignored></body></html>";
        assert_eq!(extract(html).unwrap().href(), Some("good"));
    }

    #[test]
    fn markup_inside_another_script_is_not_discovered() {
        let html =
            b"<head><script>var s = \"<link rel=c2pa-manifest href=x>\";</script><meta></head>";
        assert_eq!(extract(html), Err(Error::NotFound));
    }

    #[test]
    fn a_commented_out_element_is_not_discovered() {
        let html = b"<head><!-- <link rel=c2pa-manifest href=x> --><meta></head>";
        assert_eq!(extract(html), Err(Error::NotFound));
    }

    #[test]
    fn leading_and_trailing_whitespace_is_stripped_before_decoding() {
        let html = b"<head><script type=\"application/c2pa\">\n        aGk=\n    </script></head>";
        assert_eq!(extract(html).unwrap().store(), Some(&b"hi"[..]));
    }

    #[test]
    fn an_undecodable_script_is_malformed_not_a_hash_failure() {
        let html = b"<head><script type=application/c2pa>not base64!</script></head>";
        let err = extract(html).unwrap_err();
        assert!(matches!(err, Error::MalformedElement(_)));
        assert!(err.is_no_manifest_located());
        assert_eq!(err.code(), None);
    }

    #[test]
    fn a_link_without_an_href_is_malformed() {
        let html = b"<head><link rel=c2pa-manifest></head>";
        assert!(matches!(extract(html), Err(Error::MalformedElement(_))));
        let html = b"<head><link rel=c2pa-manifest href=\"\"></head>";
        assert!(matches!(extract(html), Err(Error::MalformedElement(_))));
    }

    #[test]
    fn a_near_miss_type_or_rel_is_not_a_manifest() {
        for html in [
            &b"<head><script type=application/c2pa+json>aGk=</script></head>"[..],
            &b"<head><script type=application/json>aGk=</script></head>"[..],
            &b"<head><script>aGk=</script></head>"[..],
            &b"<head><link rel=c2pa-manifest-x href=a></head>"[..],
            &b"<head><link rel=stylesheet href=a></head>"[..],
            &b"<head><link href=a></head>"[..],
        ] {
            assert_eq!(extract(html), Err(Error::NotFound), "{}", utf8(html));
        }
    }

    #[test]
    fn matching_is_case_insensitive_on_names_types_and_relations() {
        let html = b"<HEAD><SCRIPT TYPE=\"APPLICATION/C2PA\">aGk=</SCRIPT></HEAD>";
        assert_eq!(extract(html).unwrap().store(), Some(&b"hi"[..]));
        let html = b"<head><LINK REL=\"C2PA-Manifest\" HREF=\"m\"></head>";
        assert_eq!(extract(html).unwrap().href(), Some("m"));
    }

    #[test]
    fn a_rel_token_list_containing_the_relation_matches() {
        let html = b"<head><link rel=\"alternate c2pa-manifest\" href=m></head>";
        assert_eq!(extract(html).unwrap().href(), Some("m"));
    }

    #[test]
    fn an_implied_head_is_still_searched() {
        // No `<head>` or `</head>`: the element sits in the implied head.
        let html = b"<html><link rel=c2pa-manifest href=m><body><p>x</p></body></html>";
        assert_eq!(extract(html).unwrap().href(), Some("m"));
    }

    #[test]
    fn a_non_utf8_document_still_scans() {
        // Latin-1 bytes in the title: discovery is byte-oriented and must not
        // require the document to be UTF-8.
        let mut html =
            b"<head><title>caf\xE9</title><link rel=c2pa-manifest href=m></head>".to_vec();
        assert_eq!(extract(&html).unwrap().href(), Some("m"));
        html.extend_from_slice(b"<body>\xFF\xFE</body>");
        assert_eq!(extract(&html).unwrap().href(), Some("m"));
    }

    #[test]
    fn an_empty_store_round_trips() {
        let out = embed(DOC, b"").unwrap();
        assert_eq!(extract(&out).unwrap().store(), Some(&b""[..]));
    }

    #[test]
    fn every_byte_value_survives_the_base64_round_trip() {
        let store: Vec<u8> = (0..=255).collect();
        let out = embed(DOC, &store).unwrap();
        assert_eq!(extract(&out).unwrap().store(), Some(&store[..]));
    }
}
