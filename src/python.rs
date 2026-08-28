//! Python bindings, built with [maturin]/[PyO3] behind the `python` feature and
//! published to PyPI as `c2pa-html`.
//!
//! Documents map to and from Python `bytes`, matching the Rust API: the
//! specification treats an HTML document as a series of bytes, so a document in
//! a legacy encoding round-trips unchanged.
//!
//! A document that simply carries no manifest returns `None` from
//! [`extract`](fn.extract.html) rather than raising, because absence of
//! provenance is not an error. Everything else raises `ValueError` carrying the
//! C2PA status code when the specification defines one.
//!
//! [maturin]: https://www.maturin.rs/
//! [PyO3]: https://pyo3.rs/

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::document::Manifest;
use crate::hardbinding::{self, Algorithm, DataHash, Exclusion, Sha2};

/// Map a crate error to `ValueError`, naming the C2PA status code when the
/// specification defines one so a caller can branch on it.
fn map_err(e: crate::Error) -> PyErr {
    match e.code() {
        Some(code) => PyValueError::new_err(format!("{e} [{code}]")),
        None => PyValueError::new_err(e.to_string()),
    }
}

fn algorithm(alg: &str) -> PyResult<Algorithm> {
    Algorithm::from_id(alg).map_err(map_err)
}

/// Embed a Manifest Store inline, as a `script` element in the document head.
#[pyfunction]
fn embed<'py>(py: Python<'py>, html: &[u8], store: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let out = crate::document::embed(html, store).map_err(map_err)?;
    Ok(PyBytes::new(py, &out))
}

/// Reference an external Manifest Store, as a `link` element in the head.
#[pyfunction]
fn embed_reference<'py>(py: Python<'py>, html: &[u8], href: &str) -> PyResult<Bound<'py, PyBytes>> {
    let out = crate::document::embed_reference(html, href).map_err(map_err)?;
    Ok(PyBytes::new(py, &out))
}

/// Remove every C2PA manifest element from the document.
#[pyfunction]
fn remove<'py>(py: Python<'py>, html: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let out = crate::document::remove(html).map_err(map_err)?;
    Ok(PyBytes::new(py, &out))
}

/// The document's manifest association, or `None` when it carries none.
///
/// Returns a dict with `kind` (`"embedded"` or `"referenced"`), `start`,
/// `length`, and either `store` (bytes) or `href` (str).
#[pyfunction]
fn extract<'py>(py: Python<'py>, html: &[u8]) -> PyResult<Option<Bound<'py, PyDict>>> {
    let manifest = match crate::document::extract(html) {
        Ok(m) => m,
        // No provenance is not a failure; anything else is.
        Err(crate::Error::NotFound) => return Ok(None),
        Err(e) => return Err(map_err(e)),
    };
    let out = PyDict::new(py);
    out.set_item("start", manifest.start())?;
    out.set_item("length", manifest.length())?;
    match &manifest {
        Manifest::Embedded { store, .. } => {
            out.set_item("kind", "embedded")?;
            out.set_item("store", PyBytes::new(py, store))?;
        }
        Manifest::Referenced { href, .. } => {
            out.set_item("kind", "referenced")?;
            out.set_item("href", href.as_str())?;
        }
    }
    Ok(Some(out))
}

/// The `(start, length)` byte ranges of every C2PA manifest element in the head.
///
/// More than one means the document is rejected; this is exposed so a caller
/// can report how many were found.
#[pyfunction]
fn locate_all(html: &[u8]) -> Vec<(usize, usize)> {
    crate::document::locate_all(html)
        .into_iter()
        .map(|r| (r.start, r.len()))
        .collect()
}

fn data_hash_to_dict<'py>(py: Python<'py>, dh: &DataHash) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("alg", dh.alg.as_str())?;
    out.set_item("hash", PyBytes::new(py, &dh.hash))?;
    out.set_item(
        "exclusions",
        dh.exclusions
            .iter()
            .map(|e| (e.start, e.length))
            .collect::<Vec<_>>(),
    )?;
    Ok(out)
}

/// Compute the `c2pa.hash.data` binding for a document that already carries a
/// manifest.
///
/// `alg` is one of `sha256`, `sha384`, `sha512`. Returns a dict with `alg`,
/// `hash` (bytes), and `exclusions` (a list of `(start, length)`).
#[pyfunction]
#[pyo3(signature = (html, alg = "sha256"))]
fn compute_data_hash<'py>(py: Python<'py>, html: &[u8], alg: &str) -> PyResult<Bound<'py, PyDict>> {
    let dh = hardbinding::compute_data_hash(html, algorithm(alg)?, &Sha2).map_err(map_err)?;
    data_hash_to_dict(py, &dh)
}

/// Verify a `c2pa.hash.data` binding against a document.
///
/// Raises `ValueError` carrying the status code on mismatch or a malformed
/// exclusion; returns `None` on success.
#[pyfunction]
#[pyo3(signature = (html, hash, exclusions, alg = "sha256"))]
fn verify_data_hash(
    html: &[u8],
    hash: &[u8],
    exclusions: Vec<(usize, usize)>,
    alg: &str,
) -> PyResult<()> {
    let dh = DataHash {
        exclusions: exclusions
            .into_iter()
            .map(|(start, length)| Exclusion { start, length })
            .collect(),
        alg: algorithm(alg)?.id().to_string(),
        hash: hash.to_vec(),
        pad: Vec::new(),
        name: None,
    };
    hardbinding::verify_data_hash(html, &dh, &Sha2).map_err(map_err)
}

/// The hash an inline binding will have once a manifest is embedded, computed
/// before the manifest exists.
///
/// Because the exclusion covers the whole `script` element and embedding adds
/// no bytes outside it, the covered bytes are the document as it stands. This
/// is what makes the order hash, sign, embed possible.
#[pyfunction]
#[pyo3(signature = (html, alg = "sha256"))]
fn inline_hash_before_embed<'py>(
    py: Python<'py>,
    html: &[u8],
    alg: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let digest =
        hardbinding::inline_hash_before_embed(html, algorithm(alg)?, &Sha2).map_err(map_err)?;
    Ok(PyBytes::new(py, &digest))
}

#[pymodule]
fn c2pa_html(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(embed, m)?)?;
    m.add_function(wrap_pyfunction!(embed_reference, m)?)?;
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    m.add_function(wrap_pyfunction!(remove, m)?)?;
    m.add_function(wrap_pyfunction!(locate_all, m)?)?;
    m.add_function(wrap_pyfunction!(compute_data_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_data_hash, m)?)?;
    m.add_function(wrap_pyfunction!(inline_hash_before_embed, m)?)?;
    m.add("SCRIPT_TYPE", crate::document::SCRIPT_TYPE)?;
    m.add("LINK_REL", crate::document::LINK_REL)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
