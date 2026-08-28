//! WebAssembly bindings, built only for the `wasm32` target and published to
//! npm as `c2pa-html`.
//!
//! Documents map to and from `Uint8Array`, matching the Rust API: the
//! specification treats an HTML document as a series of bytes, so a document in
//! a legacy encoding round-trips unchanged. A document carrying no manifest
//! returns `null` from [`extract`](fn.extract.html) rather than throwing.

use wasm_bindgen::prelude::*;

use crate::document::Manifest;
use crate::hardbinding::{self, Algorithm, DataHash, Exclusion, Sha2};

/// Map a crate error to a JS error, naming the C2PA status code when the
/// specification defines one so a caller can branch on it.
fn js_err(e: crate::Error) -> JsError {
    match e.code() {
        Some(code) => JsError::new(&format!("{e} [{code}]")),
        None => JsError::new(&e.to_string()),
    }
}

fn algorithm(alg: &str) -> Result<Algorithm, JsError> {
    Algorithm::from_id(alg).map_err(js_err)
}

/// Embed a Manifest Store inline, as a `script` element in the document head.
#[wasm_bindgen(js_name = embed)]
pub fn embed(html: &[u8], store: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::document::embed(html, store).map_err(js_err)
}

/// Reference an external Manifest Store, as a `link` element in the head.
#[wasm_bindgen(js_name = embedReference)]
pub fn embed_reference(html: &[u8], href: &str) -> Result<Vec<u8>, JsError> {
    crate::document::embed_reference(html, href).map_err(js_err)
}

/// Remove every C2PA manifest element from the document.
#[wasm_bindgen(js_name = remove)]
pub fn remove(html: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::document::remove(html).map_err(js_err)
}

/// The document's manifest association, or `null` when it carries none.
///
/// Returns an object with `kind` (`"embedded"` or `"referenced"`), `start`,
/// `length`, and either `store` or `href`.
#[wasm_bindgen(js_name = extract)]
pub fn extract(html: &[u8]) -> Result<JsValue, JsError> {
    let manifest = match crate::document::extract(html) {
        Ok(m) => m,
        Err(crate::Error::NotFound) => return Ok(JsValue::NULL),
        Err(e) => return Err(js_err(e)),
    };
    let out = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&out, &"start".into(), &(manifest.start() as u32).into());
    let _ = js_sys::Reflect::set(&out, &"length".into(), &(manifest.length() as u32).into());
    match &manifest {
        Manifest::Embedded { store, .. } => {
            let _ = js_sys::Reflect::set(&out, &"kind".into(), &"embedded".into());
            let _ = js_sys::Reflect::set(
                &out,
                &"store".into(),
                &js_sys::Uint8Array::from(&store[..]).into(),
            );
        }
        Manifest::Referenced { href, .. } => {
            let _ = js_sys::Reflect::set(&out, &"kind".into(), &"referenced".into());
            let _ = js_sys::Reflect::set(&out, &"href".into(), &href.as_str().into());
        }
    }
    Ok(out.into())
}

/// Compute the `c2pa.hash.data` binding for a document that already carries a
/// manifest. Returns `{ alg, hash, exclusions }`.
#[wasm_bindgen(js_name = computeDataHash)]
pub fn compute_data_hash(html: &[u8], alg: &str) -> Result<JsValue, JsError> {
    let dh = hardbinding::compute_data_hash(html, algorithm(alg)?, &Sha2).map_err(js_err)?;
    let out = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&out, &"alg".into(), &dh.alg.as_str().into());
    let _ = js_sys::Reflect::set(
        &out,
        &"hash".into(),
        &js_sys::Uint8Array::from(&dh.hash[..]).into(),
    );
    let ranges = js_sys::Array::new();
    for e in &dh.exclusions {
        let r = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&r, &"start".into(), &(e.start as u32).into());
        let _ = js_sys::Reflect::set(&r, &"length".into(), &(e.length as u32).into());
        ranges.push(&r);
    }
    let _ = js_sys::Reflect::set(&out, &"exclusions".into(), &ranges);
    Ok(out.into())
}

/// Verify a `c2pa.hash.data` binding. Throws on mismatch; returns nothing on
/// success.
#[wasm_bindgen(js_name = verifyDataHash)]
pub fn verify_data_hash(
    html: &[u8],
    hash: &[u8],
    exclusion_starts: Vec<u32>,
    exclusion_lengths: Vec<u32>,
    alg: &str,
) -> Result<(), JsError> {
    if exclusion_starts.len() != exclusion_lengths.len() {
        return Err(JsError::new(
            "exclusion_starts and exclusion_lengths must be the same length",
        ));
    }
    let dh = DataHash {
        exclusions: exclusion_starts
            .iter()
            .zip(&exclusion_lengths)
            .map(|(&start, &length)| Exclusion {
                start: start as usize,
                length: length as usize,
            })
            .collect(),
        alg: algorithm(alg)?.id().to_string(),
        hash: hash.to_vec(),
        pad: Vec::new(),
        name: None,
    };
    hardbinding::verify_data_hash(html, &dh, &Sha2).map_err(js_err)
}

/// The hash an inline binding will have once a manifest is embedded, computed
/// before the manifest exists. This is what makes the order hash, sign, embed
/// possible.
#[wasm_bindgen(js_name = inlineHashBeforeEmbed)]
pub fn inline_hash_before_embed(html: &[u8], alg: &str) -> Result<Vec<u8>, JsError> {
    hardbinding::inline_hash_before_embed(html, algorithm(alg)?, &Sha2).map_err(js_err)
}
