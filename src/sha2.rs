// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! SHA-256, SHA-384, and SHA-512 per FIPS 180-4.
//!
//! Implemented here so the crate has no dependencies at any feature level. A
//! hash is the one primitive where writing it yourself is uncontroversial: the
//! algorithm is fully specified, it takes no key, it processes public bytes, and
//! NIST publishes vectors that pin every path. There is no secret to leak on a
//! timing side channel and no parameter to get subtly wrong — an implementation
//! either reproduces the vectors or it does not.
//!
//! What is given up is speed. RustCrypto's `sha2` dispatches to SHA-NI and
//! NEON; this does not, and runs a few times slower on large inputs. That is
//! immaterial for an HTML document and would not be for a multi-gigabyte asset,
//! which is exactly why [`crate::hardbinding::Hasher`] exists: a caller with
//! that problem injects an accelerated implementation and never touches this
//! module.
//!
//! Input is consumed a block at a time and only the final padded block or two is
//! ever copied, so hashing does not allocate a second copy of the document.

/// SHA-256 initial hash value: the first 32 bits of the fractional parts of the
/// square roots of the first eight primes (2, 3, 5, 7, 11, 13, 17, 19).
const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-512 initial hash value: the first 64 bits of the fractional parts of the
/// square roots of the first eight primes.
const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// SHA-384 initial hash value: the first 64 bits of the fractional parts of the
/// square roots of the *ninth through sixteenth* primes (23 … 53). A distinct
/// IV is what makes SHA-384 more than truncated SHA-512.
const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Digest the input with SHA-256.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = H256;
    each_block_32(data, |block| compress256(&mut h, block));
    h.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// Digest the input with SHA-384: SHA-512's compression under a different
/// initial state, truncated to 48 bytes.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut h = H384;
    each_block_64(data, |block| compress512(&mut h, block));
    h.iter().flat_map(|w| w.to_be_bytes()).take(48).collect()
}

/// Digest the input with SHA-512.
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut h = H512;
    each_block_64(data, |block| compress512(&mut h, block));
    h.iter().flat_map(|w| w.to_be_bytes()).collect()
}

/// Feed `data` to `f` as 64-byte blocks, then the FIPS 180-4 padding: a `0x80`
/// byte, zeros, and the message length in bits as a big-endian `u64`.
fn each_block_32(data: &[u8], mut f: impl FnMut(&[u8; 64])) {
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        f(block.try_into().expect("chunks_exact yields 64 bytes"));
    }
    let rest = blocks.remainder();

    // The length field must fit after the `0x80`; if it does not, the padding
    // spills into a second block.
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let len = if rest.len() + 1 + 8 <= 64 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[len - 8..len].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..len].chunks_exact(64) {
        f(block.try_into().expect("chunks_exact yields 64 bytes"));
    }
}

/// As [`each_block_32`], with 128-byte blocks and a 128-bit length field.
fn each_block_64(data: &[u8], mut f: impl FnMut(&[u8; 128])) {
    let mut blocks = data.chunks_exact(128);
    for block in &mut blocks {
        f(block.try_into().expect("chunks_exact yields 128 bytes"));
    }
    let rest = blocks.remainder();

    let mut tail = [0u8; 256];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let len = if rest.len() + 1 + 16 <= 128 { 128 } else { 256 };
    let bits = (data.len() as u128).wrapping_mul(8);
    tail[len - 16..len].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..len].chunks_exact(128) {
        f(block.try_into().expect("chunks_exact yields 128 bytes"));
    }
}

#[rustfmt::skip]
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes(
            block[i * 4..i * 4 + 4]
                .try_into()
                .expect("four bytes per word"),
        );
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (dst, src) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *dst = dst.wrapping_add(src);
    }
}

#[rustfmt::skip]
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u64::from_be_bytes(
            block[i * 8..i * 8 + 8]
                .try_into()
                .expect("eight bytes per word"),
        );
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (dst, src) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *dst = dst.wrapping_add(src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // FIPS 180-4 / NIST CAVS known-answer vectors.

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(&[b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha512_matches_nist_vectors() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex(&sha512(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
        assert_eq!(
            hex(&sha512(&[b'a'; 1_000_000])),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }

    #[test]
    fn sha384_matches_nist_vectors() {
        assert_eq!(
            hex(&sha384(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&sha384(&[b'a'; 1_000_000])),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b\
             07b8b3dc38ecc4ebae97ddd87f3d8985"
        );
    }

    #[test]
    fn digest_lengths_are_fixed() {
        assert_eq!(sha256(b"x").len(), 32);
        assert_eq!(sha384(b"x").len(), 48);
        assert_eq!(sha512(b"x").len(), 64);
    }

    #[test]
    fn sha384_is_a_prefix_of_nothing_it_should_not_be() {
        // SHA-384 is not truncated SHA-512: it uses a different initial state.
        assert_ne!(sha384(b"abc")[..], sha512(b"abc")[..48]);
    }

    /// Every length that straddles a block boundary or forces the padding into
    /// a second block. These are where a length-field or spill bug hides.
    #[test]
    fn block_boundary_lengths_are_handled() {
        // For SHA-256: blocks are 64 bytes, the length field needs 8.
        for len in [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129] {
            let data = vec![b'a'; len];
            let d = sha256(&data);
            assert_eq!(d.len(), 32, "sha256 length {len}");
            // Changing the final byte must change the digest.
            if len > 0 {
                let mut other = data.clone();
                other[len - 1] = b'b';
                assert_ne!(sha256(&other), d, "sha256 length {len} ignored a byte");
            }
        }
        // For SHA-512: blocks are 128 bytes, the length field needs 16.
        for len in [0, 1, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256] {
            let data = vec![b'a'; len];
            assert_eq!(sha512(&data).len(), 64, "sha512 length {len}");
            assert_eq!(sha384(&data).len(), 48, "sha384 length {len}");
            if len > 0 {
                let mut other = data.clone();
                other[len - 1] = b'b';
                assert_ne!(sha512(&other), sha512(&data), "sha512 length {len}");
            }
        }
    }

    /// The padded length must depend on the message length, not just its bytes.
    #[test]
    fn length_extension_inputs_differ() {
        assert_ne!(sha256(b"a"), sha256(b"a\x00"));
        assert_ne!(sha512(b"a"), sha512(b"a\x00"));
    }

    fn primes(n: usize) -> Vec<u128> {
        let mut out: Vec<u128> = Vec::with_capacity(n);
        let mut c: u128 = 2;
        while out.len() < n {
            if out
                .iter()
                .take_while(|p| *p * *p <= c)
                .all(|p| !c.is_multiple_of(*p))
            {
                out.push(c);
            }
            c += 1;
        }
        out
    }

    /// Integer `k`-th root of `x`, by binary search. Exact, so the derived
    /// constants carry no floating-point rounding.
    fn iroot(x: u128, k: u32) -> u128 {
        if x == 0 {
            return 0;
        }
        let (mut lo, mut hi) = (1u128, 1u128 << (x.ilog2() / k + 2));
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            match mid.checked_pow(k) {
                Some(v) if v <= x => lo = mid,
                _ => hi = mid - 1,
            }
        }
        lo
    }

    /// The first `bits` bits of the fractional part of `p ** (1 / root)`.
    fn frac_bits(p: u128, root: u32, bits: u32) -> u128 {
        iroot(p << (root * bits), root) - (iroot(p, root) << bits)
    }

    /// The SHA-256 tables are not magic numbers to be trusted on sight: FIPS
    /// 180-4 *defines* them as fractional parts of roots of the small primes,
    /// so they can be regenerated and compared.
    ///
    /// This is what rules out a transcription error in a table that would
    /// otherwise only surface as an interop failure against an external
    /// validator. SHA-512's tables need 256-bit intermediates to derive this
    /// way, so they are pinned by the NIST vectors above instead.
    #[test]
    fn sha256_constants_are_derived_from_the_primes() {
        let ps = primes(64);

        // K: first 32 bits of the fractional parts of the cube roots of the
        // first 64 primes.
        for (i, &p) in ps.iter().enumerate() {
            assert_eq!(
                K256[i] as u128,
                frac_bits(p, 3, 32),
                "K256[{i}] does not match the cube root of prime {p}"
            );
        }

        // IV: first 32 bits of the fractional parts of the square roots of the
        // first 8 primes.
        for (i, &p) in ps.iter().take(8).enumerate() {
            assert_eq!(
                H256[i] as u128,
                frac_bits(p, 2, 32),
                "H256[{i}] does not match the square root of prime {p}"
            );
        }
    }

    #[test]
    fn the_derivation_helpers_are_themselves_correct() {
        // Guard against a vacuous pass: if `frac_bits` were broken, the test
        // above could agree with a wrong table.
        assert_eq!(primes(8), [2, 3, 5, 7, 11, 13, 17, 19]);
        assert_eq!(iroot(27, 3), 3);
        assert_eq!(iroot(26, 3), 2);
        assert_eq!(iroot(1 << 96, 3), 1 << 32);
        // sqrt(2) = 1.41421356…; the fraction is 0.41421356… × 2^32.
        assert_eq!(frac_bits(2, 2, 32), 0x6a09e667);
        // cbrt(2) = 1.25992105…
        assert_eq!(frac_bits(2, 3, 32), 0x428a2f98);
    }

    #[test]
    fn sha384_uses_a_distinct_iv_from_sha512() {
        // SHA-384 is defined by a different initial state, not by truncation.
        assert_ne!(H384, H512);
    }
}
