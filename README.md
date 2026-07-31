# c2pa-html

C2PA manifest embedding, referencing, and hard binding for HTML documents.

Implements the *Embedding Manifests into HTML* section of the [C2PA Technical
Specification](https://spec.c2pa.org/): a C2PA Manifest Store carried inline as
the Base64 content of a `<script type="application/c2pa">` element, or
referenced externally by a `<link rel="c2pa-manifest">` element, both in the
document `head`.

```toml
[dependencies]
c2pa-html = "0.1"
```

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

## Related

| crate | method |
|---|---|
| [`c2pa-structured-text`](https://crates.io/crates/c2pa-structured-text) | structured text: ASCII-armoured manifest in a comment |
| [`c2pa-unstructured-text`](https://crates.io/crates/c2pa-unstructured-text) | unstructured text: Unicode variation selectors |

HTML is a file format, so its binding hashes stored bytes with no normalization.
The text methods differ deliberately: structured text also hashes raw bytes but
has no element to exclude, and unstructured text normalizes to NFC because
clipboard-portable text may arrive in any normalization form.

## License

MIT OR Apache-2.0.
