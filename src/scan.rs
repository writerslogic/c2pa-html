// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! A byte-oriented tag scanner, enough of HTML to find the `head` and the
//! elements in it.
//!
//! The specification directs a validator to treat the file "as a series of
//! bytes (vs. text)", so this operates on `&[u8]` and never requires the
//! document to be UTF-8. Legacy encodings that are ASCII-compatible (the
//! `windows-125x` family, Shift_JIS, EUC-KR) scan correctly because every byte
//! this code tests for is ASCII.
//!
//! This is deliberately not a conforming HTML parser. It resolves exactly what
//! discovery needs: tag boundaries, attribute values in all three quoting
//! forms, comments, and raw-text elements whose contents must not be mistaken
//! for markup. Everything else about HTML — implied tags, foreign content,
//! error recovery — is out of scope, and where behaviour diverges the divergence
//! is documented on the function that owns it.

use std::ops::Range;

/// Elements whose content is raw text, not markup. A `<link rel="c2pa-manifest">`
/// written inside a JavaScript string is text, not an element, and must not be
/// discovered as one.
///
/// `noscript` is included because, per the HTML parsing algorithm, when
/// scripting is enabled (the normal case for essentially every deployed
/// browser) its content is tokenized as raw text and never becomes part of
/// the DOM — a manifest-shaped element inside it is not a live association.
///
/// `template` content is *not* included here even though it has the same
/// "not live in the main document" property: unlike the other raw-text
/// elements, a `template`'s content is parsed as real markup (into a
/// detached template-contents fragment), not skipped as text, so folding it
/// into this list would be wrong — it needs its own fragment-fencing, which
/// this scanner does not yet implement. A manifest-shaped element inside
/// `<head><template>...</template></head>` is therefore still (incorrectly)
/// discovered as a live candidate; this is a known, documented gap.
const RAW_TEXT: [&str; 5] = ["script", "style", "textarea", "title", "noscript"];

/// A start or end tag located in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tag {
    /// The tag name, ASCII-lowercased.
    pub name: String,
    /// Byte offset of the opening `<`.
    pub start: usize,
    /// Byte offset just past the closing `>`.
    pub end: usize,
    /// True for `</name>`.
    pub is_end: bool,
    /// Attribute names (ASCII-lowercased) and their raw values.
    pub attrs: Vec<(String, String)>,
}

impl Tag {
    /// The value of `name`, or `None` if the attribute is absent. A valueless
    /// attribute yields `Some("")`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether the attribute `name` holds `value`, compared as the whole value
    /// with surrounding ASCII whitespace trimmed, ASCII case-insensitively.
    pub fn attr_is(&self, name: &str, value: &str) -> bool {
        self.attr(name).is_some_and(|v| {
            v.trim_matches(is_html_space_char)
                .eq_ignore_ascii_case(value)
        })
    }

    /// Whether the attribute `name` is a space-separated token list containing
    /// `token`, compared ASCII case-insensitively. This is how HTML defines
    /// `rel`.
    pub fn attr_has_token(&self, name: &str, token: &str) -> bool {
        self.attr(name).is_some_and(|v| {
            v.split(is_html_space_char)
                .any(|t| t.eq_ignore_ascii_case(token))
        })
    }
}

/// HTML's definition of whitespace: tab, LF, FF, CR, space. Notably *not*
/// vertical tab, which `u8::is_ascii_whitespace` includes.
fn is_html_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

fn is_html_space_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0C' | '\r' | ' ')
}

/// Trim leading and trailing HTML whitespace from a byte slice.
pub(crate) fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_html_space(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !is_html_space(b))
        .map_or(start, |p| p + 1);
    &bytes[start..end]
}

fn lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| b.to_ascii_lowercase() as char)
        .collect()
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Every start and end tag in the document, in source order.
///
/// The contents of raw-text elements are skipped, so the tags inside a
/// `<script>` body are not reported; the element's own end tag is.
pub(crate) fn tags(html: &[u8]) -> Vec<Tag> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < html.len() {
        if html[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &html[i..];
        if rest.starts_with(b"<!--") {
            i = find(html, i + 4, b"-->").map_or(html.len(), |p| p + 3);
            continue;
        }
        // Doctype, CDATA, and processing instructions: skip to the next `>`.
        if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
            i = html[i + 1..]
                .iter()
                .position(|&b| b == b'>')
                .map_or(html.len(), |p| i + 1 + p + 1);
            continue;
        }
        let is_end = rest.starts_with(b"</");
        let name_start = i + if is_end { 2 } else { 1 };
        if !html.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            // A `<` that does not open a tag is ordinary text.
            i += 1;
            continue;
        }
        let mut j = name_start;
        while html
            .get(j)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
        {
            j += 1;
        }
        let name = lower(&html[name_start..j]);
        let (attrs, end) = attributes(html, j);
        let raw_text = !is_end && RAW_TEXT.contains(&name.as_str());
        let start = i;
        i = if raw_text {
            // Jump to the matching end tag so the contents are never tokenized.
            // An unterminated raw-text element swallows the rest of the
            // document, exactly as a browser treats it.
            raw_text_end(html, end, &name).unwrap_or(html.len())
        } else {
            end
        };
        out.push(Tag {
            name,
            start,
            end,
            is_end,
            attrs,
        });
    }
    out
}

/// Offset of the `<` opening the end tag that closes a raw-text element.
fn raw_text_end(html: &[u8], from: usize, name: &str) -> Option<usize> {
    let n = name.as_bytes();
    let mut i = from;
    while i + 2 + n.len() <= html.len() {
        if html[i] == b'<'
            && html[i + 1] == b'/'
            && html[i + 2..i + 2 + n.len()].eq_ignore_ascii_case(n)
        {
            let after = i + 2 + n.len();
            if html
                .get(after)
                .is_none_or(|&b| is_html_space(b) || b == b'>' || b == b'/')
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Parse a tag's attributes starting just past its name. Returns the attributes
/// and the offset just past the closing `>` (or the end of the document, for an
/// unterminated tag).
///
/// All three HTML quoting forms are accepted: double-quoted, single-quoted, and
/// unquoted. An unquoted value runs to the next whitespace or `>`, so `/` is
/// part of the value — which is what HTML specifies, and why
/// `<link href=a/ rel=b>` has an `href` of `a/`.
fn attributes(html: &[u8], mut i: usize) -> (Vec<(String, String)>, usize) {
    let mut attrs: Vec<(String, String)> = Vec::new();
    loop {
        while html.get(i).is_some_and(|&b| is_html_space(b)) {
            i += 1;
        }
        match html.get(i) {
            None => return (attrs, html.len()),
            Some(b'>') => return (attrs, i + 1),
            // A `/` between attributes is ignored; `/>` closes the tag on the
            // next pass through the `>` arm.
            Some(b'/') => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let name_start = i;
        while html
            .get(i)
            .is_some_and(|&b| !is_html_space(b) && !matches!(b, b'=' | b'>' | b'/'))
        {
            i += 1;
        }
        if i == name_start {
            // Defensive: no byte consumed means an unexpected delimiter. Skip it
            // rather than spin.
            i += 1;
            continue;
        }
        let name = lower(&html[name_start..i]);

        let mut k = i;
        while html.get(k).is_some_and(|&b| is_html_space(b)) {
            k += 1;
        }
        let value = if html.get(k) == Some(&b'=') {
            k += 1;
            while html.get(k).is_some_and(|&b| is_html_space(b)) {
                k += 1;
            }
            match html.get(k) {
                Some(&q @ (b'"' | b'\'')) => {
                    k += 1;
                    let start = k;
                    while html.get(k).is_some_and(|&b| b != q) {
                        k += 1;
                    }
                    let v = String::from_utf8_lossy(&html[start..k]).into_owned();
                    // Step past the closing quote when there is one.
                    i = (k + 1).min(html.len());
                    v
                }
                Some(_) => {
                    let start = k;
                    while html.get(k).is_some_and(|&b| !is_html_space(b) && b != b'>') {
                        k += 1;
                    }
                    let v = String::from_utf8_lossy(&html[start..k]).into_owned();
                    i = k;
                    v
                }
                None => {
                    i = html.len();
                    String::new()
                }
            }
        } else {
            String::new()
        };

        // First occurrence wins, as in HTML.
        if !attrs.iter().any(|(k, _)| *k == name) {
            attrs.push((name, value));
        }
    }
}

/// The byte range of the `head` element's content, and the offset of its end
/// tag if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub content: Range<usize>,
    /// Offset of the `<` opening `</head>`, when the document has one.
    pub end_tag: Option<usize>,
}

/// Resolve the `head` element's extent.
///
/// HTML permits both `<head>` and `</head>` to be omitted, in which case the
/// element is implied. Rather than implement the full insertion-mode machinery,
/// the head is taken to start after `<head>` (or after `<html>`, or at the
/// start of the document) and to end at the first `</head>`, `<body>`,
/// `</html>`, or start tag that HTML's "in head" insertion mode reprocesses in
/// the body.
///
/// This keeps discovery aligned with a conforming HTML parser even when the
/// author omitted both `</head>` and `<body>`.
pub(crate) fn head(html: &[u8], tags: &[Tag]) -> Head {
    let start = tags
        .iter()
        .find(|t| !t.is_end && t.name == "head")
        .or_else(|| tags.iter().find(|t| !t.is_end && t.name == "html"))
        .map_or(0, |t| t.end);

    let terminator = tags.iter().find(|t| {
        t.start >= start
            && ((t.is_end && (t.name == "head" || t.name == "html"))
                || (!t.is_end
                    && (t.name == "body"
                        || !matches!(
                            t.name.as_str(),
                            "base"
                                | "basefont"
                                | "bgsound"
                                | "link"
                                | "meta"
                                | "noframes"
                                | "noscript"
                                | "script"
                                | "style"
                                | "template"
                                | "title"
                        ))))
    });

    Head {
        content: start..terminator.map_or(html.len(), |t| t.start),
        end_tag: tags
            .iter()
            .find(|t| t.is_end && t.name == "head" && t.start >= start)
            .map(|t| t.start),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(html: &[u8]) -> Vec<String> {
        tags(html)
            .into_iter()
            .map(|t| {
                if t.is_end {
                    format!("/{}", t.name)
                } else {
                    t.name
                }
            })
            .collect()
    }

    #[test]
    fn tag_offsets_bracket_the_tag() {
        let html = b"<p><a href=\"x\">hi</a>";
        let ts = tags(html);
        assert_eq!(&html[ts[1].start..ts[1].end], b"<a href=\"x\">");
        assert_eq!(&html[ts[2].start..ts[2].end], b"</a>");
    }

    #[test]
    fn names_are_lowercased_and_end_tags_marked() {
        assert_eq!(
            names(b"<HTML><Head></HEAD><BODY></body></html>"),
            ["html", "head", "/head", "body", "/body", "/html"]
        );
    }

    #[test]
    fn accepts_all_three_attribute_quoting_forms() {
        let ts = tags(br#"<link rel="a" href='b' type=c/d>"#);
        let t = &ts[0];
        assert_eq!(t.attr("rel"), Some("a"));
        assert_eq!(t.attr("href"), Some("b"));
        assert_eq!(t.attr("type"), Some("c/d"));
    }

    #[test]
    fn unquoted_value_keeps_a_trailing_slash() {
        // HTML only treats `/` as special before `>`, so the value is `a/`.
        let ts = tags(b"<link href=a/ rel=b>");
        assert_eq!(ts[0].attr("href"), Some("a/"));
        assert_eq!(ts[0].attr("rel"), Some("b"));
    }

    #[test]
    fn self_closing_syntax_ends_the_tag() {
        let ts = tags(br#"<link rel="c2pa-manifest" href="m.c2pa"/><meta>"#);
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0].attr("href"), Some("m.c2pa"));
        assert_eq!(ts[1].name, "meta");
    }

    #[test]
    fn valueless_attribute_is_empty_not_absent() {
        let ts = tags(b"<script defer type=application/c2pa>");
        assert_eq!(ts[0].attr("defer"), Some(""));
        assert_eq!(ts[0].attr("missing"), None);
    }

    #[test]
    fn attribute_names_are_lowercased_and_first_wins() {
        let ts = tags(br#"<link REL="a" rel="b">"#);
        assert_eq!(ts[0].attr("rel"), Some("a"));
    }

    #[test]
    fn attr_is_trims_and_ignores_case() {
        let ts = tags(br#"<script type=" APPLICATION/C2PA ">"#);
        assert!(ts[0].attr_is("type", "application/c2pa"));
        let ts = tags(br#"<script type="application/c2pa+json">"#);
        assert!(!ts[0].attr_is("type", "application/c2pa"));
    }

    #[test]
    fn attr_has_token_splits_a_relation_list() {
        let ts = tags(br#"<link rel="preload C2PA-Manifest">"#);
        assert!(ts[0].attr_has_token("rel", "c2pa-manifest"));
        let ts = tags(br#"<link rel="not-c2pa-manifest">"#);
        assert!(!ts[0].attr_has_token("rel", "c2pa-manifest"));
    }

    #[test]
    fn comments_and_doctypes_are_skipped() {
        assert_eq!(
            names(b"<!DOCTYPE html><!-- <link rel=x> --><head></head>"),
            ["head", "/head"]
        );
    }

    #[test]
    fn an_unterminated_comment_swallows_the_rest() {
        assert_eq!(names(b"<head><!-- <link rel=x>"), ["head"]);
    }

    #[test]
    fn markup_inside_a_script_body_is_not_tokenized() {
        let html = br#"<head><script>var s = "<link rel=c2pa-manifest>";</script></head>"#;
        assert_eq!(names(html), ["head", "script", "/script", "/head"]);
    }

    #[test]
    fn a_lone_angle_bracket_is_text() {
        assert_eq!(names(b"<p>a < b</p>"), ["p", "/p"]);
    }

    #[test]
    fn head_bounds_from_explicit_tags() {
        let html = b"<html><head><meta></head><body><link rel=c2pa-manifest></body></html>";
        let h = head(html, &tags(html));
        let inner = &html[h.content.clone()];
        assert_eq!(inner, b"<meta>");
        assert_eq!(
            &html[h.end_tag.unwrap()..h.end_tag.unwrap() + 7],
            b"</head>"
        );
    }

    #[test]
    fn head_is_implied_when_the_tags_are_omitted() {
        let html = b"<html><meta><body><p>x";
        let h = head(html, &tags(html));
        assert_eq!(&html[h.content.clone()], b"<meta>");
        assert_eq!(h.end_tag, None);
    }

    #[test]
    fn flow_content_implicitly_closes_the_head() {
        let html = b"<html><meta><p>x<link rel=c2pa-manifest href=m.c2pa>";
        let h = head(html, &tags(html));
        assert_eq!(&html[h.content], b"<meta>");
    }

    #[test]
    fn head_ends_at_the_document_end_when_nothing_terminates_it() {
        let html = b"<head><meta>";
        let h = head(html, &tags(html));
        assert_eq!(h.content, 6..html.len());
    }

    #[test]
    fn trim_uses_the_html_whitespace_set() {
        assert_eq!(trim(b" \t\r\n\x0Cabc \n"), b"abc");
        // Vertical tab is not HTML whitespace, so it survives.
        assert_eq!(trim(b"\x0Babc"), b"\x0Babc");
        assert_eq!(trim(b"   "), b"");
    }
}
