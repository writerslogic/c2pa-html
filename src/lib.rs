// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA manifest embedding, referencing, and hard binding for HTML documents.
//!
//! Implements the *Embedding Manifests into HTML* section of the C2PA Technical
//! Specification: a C2PA Manifest Store carried inline as the Base64 content of
//! a `<script type="application/c2pa">` element, or referenced externally by a
//! `<link rel="c2pa-manifest">` element, both in the document `head`.
//!
//! # Scope
//!
//! - **Association** ([`document`]): discover, embed, reference, and remove.
//! - **Hard binding** ([`hardbinding`]): the exact `c2pa.hash.data` coverage,
//!   with compute and verify.
//!
//! Signature verification, certificate trust, assertion validation, and
//! resolution of an external manifest URI are not implemented here.
//!
//! # Bytes, not text
//!
//! The specification directs a validator to treat the document "as a series of
//! bytes (vs. text)", so every entry point takes `&[u8]` and returns `Vec<u8>`.
//! A document in a legacy ASCII-compatible encoding scans correctly, and byte
//! offsets mean what the hard binding says they mean.
//!
//! # Zero dependencies, no features
//!
//! Discovery, embedding, Base64, SHA-2, and the binding algorithm are all
//! in-crate. There is nothing to enable and nothing to pull in: the dependency
//! list is empty in every configuration.
//!
//! Hashing still goes through [`hardbinding::Hasher`], with [`hardbinding::Sha2`]
//! as the built-in implementation. A caller with a reason to substitute — an
//! accelerated digest for a large asset, or one the host runtime already
//! provides — passes their own.
//!
//! # Examples
//!
//! Reference an external Manifest Store, which the specification prefers:
//!
//! ```
//! use c2pa_html::document;
//!
//! let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
//! let out = document::embed_reference(page, "https://fabrikam.example/m.c2pa").unwrap();
//!
//! let manifest = document::extract(&out).unwrap();
//! assert_eq!(manifest.href(), Some("https://fabrikam.example/m.c2pa"));
//! ```
//!
//! Or carry the Manifest Store inline:
//!
//! ```
//! use c2pa_html::document;
//!
//! let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
//! let out = document::embed(page, b"manifest-store-bytes").unwrap();
//!
//! assert_eq!(
//!     document::extract(&out).unwrap().store(),
//!     Some(&b"manifest-store-bytes"[..])
//! );
//! // Removing the manifest restores the document byte for byte.
//! assert_eq!(document::remove(&out).unwrap(), page);
//! ```
//!
//! Bind the document:
//!
//! ```
//! use c2pa_html::document;
//! use c2pa_html::hardbinding::{compute_data_hash, verify_data_hash, Algorithm, Sha2};
//!
//! let page = b"<html>\n<head>\n    <title>Example</title>\n</head>\n<body></body>\n</html>";
//! let out = document::embed(page, b"manifest-store-bytes").unwrap();
//!
//! let binding = compute_data_hash(&out, Algorithm::Sha256, &Sha2).unwrap();
//! assert!(verify_data_hash(&out, &binding, &Sha2).is_ok());
//! ```
//!
//! # Relationship to the text bindings
//!
//! HTML is a file format, so its binding hashes stored bytes with no
//! normalization, and re-serializing the document invalidates it by design. The
//! text methods differ deliberately: A.9 structured text also hashes raw bytes
//! but has no element to exclude, and A.8 unstructured text normalizes to NFC
//! because clipboard-portable text may arrive in any normalization form. See
//! [`c2pa-structured-text`] and [`c2pa-unstructured-text`].
//!
//! [`c2pa-structured-text`]: https://crates.io/crates/c2pa-structured-text
//! [`c2pa-unstructured-text`]: https://crates.io/crates/c2pa-unstructured-text

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

mod base64;
mod scan;
mod sha2;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(all(feature = "python", not(target_arch = "wasm32")))]
mod python;

pub mod document;
/// Errors from locating a manifest element or validating the hard binding, and
/// the C2PA status codes they map to.
pub mod error;
pub mod hardbinding;

pub use document::{embed, embed_reference, extract, locate_all, remove, Manifest};
pub use error::Error;
