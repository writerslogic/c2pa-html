# c2pa-html

_C2PA manifest embedding, referencing, and hard binding for HTML documents._

<p align="center">
  <a href="https://crates.io/crates/c2pa-html"><img src="https://img.shields.io/crates/v/c2pa-html.svg" alt="crates.io"></a>
  <a href="https://docs.rs/c2pa-html"><img src="https://docs.rs/c2pa-html/badge.svg" alt="docs.rs"></a>
  <a href="https://github.com/writerslogic/c2pa-html/actions/workflows/ci.yml"><img src="https://github.com/writerslogic/c2pa-html/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/writerslogic/c2pa-html"><img src="https://api.securityscorecards.dev/projects/github.com/writerslogic/c2pa-html/badge" alt="OpenSSF Scorecard"></a>
  <a href="#license"><img src="https://img.shields.io/crates/l/c2pa-html.svg" alt="License"></a>
</p>

## Overview

Implements the **Embedding Manifests into HTML** section of the [C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_embedding_manifests_into_html): a C2PA Manifest Store carried inline as the Base64 content of a `<script type="application/c2pa">` element, or referenced externally by a `<link rel="c2pa-manifest">` element, both in the document `head`.

```html
<head>
    <script type="application/c2pa">...Base64 Manifest Store...</script>
</head>
```

```toml
[dependencies]
c2pa-html = "0.2"
```

The same crate is published for JavaScript/WebAssembly and Python, built from this source:

```bash
npm install c2pa-html   # wasm-bindgen build
pip install c2pa-html   # PyO3 abi3 wheel, CPython 3.9+
```

HTML has its own embedding clause, so the structured-text method explicitly does
not apply to it — that method covers `text/*` formats *"not already covered by a
format-specific embedding section"*.

This crate owns two things:

1. **The association** — discover, embed, reference, and remove the `script` or `link` element.
2. **The hard binding** — the exact `c2pa.hash.data` coverage for HTML, with compute and verify.

Signature verification, certificate trust, assertion validation, and resolution
of an external manifest URI are not reimplemented here.

> [!NOTE]
> Not certified or conformance-tested by the C2PA. It implements the embedding and hard binding as specified.

## What it does

| | |
|---|---|
| `document` | discover, embed, reference, and remove a manifest association |
| `hardbinding` | the exact `c2pa.hash.data` coverage, with compute and verify |

Signature verification, certificate trust, assertion validation, and resolution
of an external manifest URI are out of scope.

## Reference an external manifest

The specification prefers this form.

```rust
use c2pa_html::document;

let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
let out = document::embed_reference(page, "https://fabrikam.example/m.c2pa")?;

let manifest = document::extract(&out)?;
assert_eq!(manifest.href(), Some("https://fabrikam.example/m.c2pa"));
# Ok::<(), c2pa_html::Error>(())
```

## Carry the manifest inline

```rust
use c2pa_html::document;

let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
let out = document::embed(page, b"manifest-store-bytes")?;

assert_eq!(
    document::extract(&out)?.store(),
    Some(&b"manifest-store-bytes"[..])
);
// Removing the manifest restores the document byte for byte.
assert_eq!(document::remove(&out)?, page);
# Ok::<(), c2pa_html::Error>(())
```

## Bind the document

```rust
use c2pa_html::document;
use c2pa_html::hardbinding::{compute_data_hash, verify_data_hash, Algorithm, Sha2};

let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
let out = document::embed(page, b"manifest-store-bytes")?;

let binding = compute_data_hash(&out, Algorithm::Sha256, &Sha2)?;
assert!(verify_data_hash(&out, &binding, &Sha2).is_ok());
# Ok::<(), c2pa_html::Error>(())
```

## Binding coverage

- **Inline** — one exclusion range covering the entire `script` element,
  `<script` through `</script>` inclusive. The hash is over the document with
  that range removed.
- **External** — no exclusion range at all. The hash is over the entire
  document, `link` element included, so the manifest URI cannot be swapped
  without breaking the binding.

The hash is over the bytes of the document *as stored*, with no normalization.
Anything that re-serializes the HTML — a CMS, a CDN, a formatter that rewrites
quote styles or collapses whitespace — shifts byte offsets and invalidates the
binding. That is by design: re-serialization is a content modification. Embed
after the final serialization step, or use an external manifest.

### The inline hash can be computed before the manifest exists

Because the exclusion covers the *entire* script element, the covered bytes are
the document with the element cut out — and `embed` adds no bytes outside the
element, so that is the original document. Signing an inline HTML manifest needs
no placeholder-reserve-then-fill dance: **hash, sign, embed**.

```rust
use c2pa_html::hardbinding::inline_hash_before_embed;
```

An external manifest has no exclusion, so the `link` element is inside the hash
and the order reverses: insert the `link` first, then hash.

## Discovery

Scoped to the document `head`, byte-oriented, and tolerant of how HTML is
actually written:

- all three attribute quoting forms — `rel="x"`, `rel='x'`, `rel=x`
- ASCII case-insensitive tag names, attribute names, `type`, and `rel`
- `rel` as a space-separated token list, per HTML
- `link` matched on `rel` alone; `type="application/c2pa"` is optional
- comments, doctypes, and the contents of other `script` and `style` elements
  are never mistaken for markup
- an implied `head` (both tags omitted) is still searched

A document shall carry at most one association. Two `script` elements, two
`link` elements, or one of each are all rejected with the specified
`manifest.html.multipleManifests` failure — the manifests were located, and the
document is rejected for carrying too many.

Finding nothing carries no status code (it is simply an unsigned document), and
neither does an element that matches but yields no Manifest Store — the
specification names no code for that, and the fail-safe reading is that nothing
was obtained. `Error::is_no_manifest_located()` draws the line a caller actually
needs: "carries no provenance" versus "carried provenance that was rejected".

## Bytes, not text

The specification directs a validator to treat the document "as a series of
bytes (vs. text)", so every entry point takes `&[u8]` and returns `Vec<u8>`. A
document in a legacy ASCII-compatible encoding scans correctly, and byte offsets
mean what the hard binding says they mean.

## Zero dependencies, no features

Discovery, embedding, Base64, SHA-2, and the binding algorithm are all in-crate.
There is nothing to enable and nothing to pull in — the dependency list is empty
in every configuration.

SHA-256/384/512 are implemented against FIPS 180-4 and tested against the NIST
vectors. A hash is the one primitive where writing it yourself is
uncontroversial: fully specified, no key, public input, no timing side channel,
and published vectors that pin every path.

What that gives up is speed — no SHA-NI, no NEON. Immaterial for an HTML
document; it would not be for a multi-gigabyte asset, which is why hashing goes
through the `Hasher` trait. A caller with that problem injects an accelerated
implementation and never touches the built-in one.

## Related Crates

Part of a family of single-purpose crates, one per C2PA embedding method. Each
is standalone and independently versioned.

| Crate | Description |
|---|---|
| [c2pa-structured-text](https://crates.io/crates/c2pa-structured-text) | Structured text: ASCII-armoured manifest in a comment or front matter |
| [c2pa-unstructured-text](https://crates.io/crates/c2pa-unstructured-text) | Unstructured text: invisible Unicode variation-selector run |
| [c2pa-http](https://crates.io/crates/c2pa-http) | HTTP: the `c2pa-manifest` `Link` header, with a Tower middleware |
| [c2pa-text-binding](https://crates.io/crates/c2pa-text-binding) | Soft binding and content fingerprinting for text assets |
| [c2pa-vtt](https://crates.io/crates/c2pa-vtt) | WebVTT caption and subtitle embedding |
| [c2pa-zip](https://crates.io/crates/c2pa-zip) | ZIP-based documents: EPUB, DOCX, ODT, OXPS |
| [c2pa-warc](https://crates.io/crates/c2pa-warc) | WARC web archive embedding (ISO 28500) |
| [c2pa-fonts](https://crates.io/crates/c2pa-fonts) | OpenType/TrueType (SFNT) font embedding |
| [c2pa-ml](https://crates.io/crates/c2pa-ml) | ML model containers: GGUF, SafeTensors, ONNX |
| [c2pa](https://crates.io/crates/c2pa) | Official C2PA SDK |

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](./SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Built by [WritersLogic](https://writerslogic.com)
