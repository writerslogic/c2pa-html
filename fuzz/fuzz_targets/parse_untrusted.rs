#![no_main]

use c2pa_html::{extract, locate_all};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = locate_all(data);
    let _ = extract(data);
});
