// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 NC Software Engineering
//
// This file is part of privatale-cli.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use privatale_core::{
    envelope::{self, Context, Error},
    framing,
};

fn context() -> Context {
    Context {
        owner_id: b"synthetic-owner".to_vec(),
        doc_id: [2; 16],
        item_id: [3; 16],
        key_version: 1,
        format_version: 0,
    }
}

fn hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg_attr(test, test)]
pub fn independent_pte0_golden_vectors() {
    let csv = include_str!("../../../test-vectors/pte0.csv");
    let rows: Vec<_> = csv.lines().skip(1).collect();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let fields: Vec<_> = row.split(',').collect();
        assert_eq!(fields.len(), 10);
        let key: [u8; 32] = hex(fields[0]).try_into().unwrap();
        let nonce: [u8; 24] = hex(fields[1]).try_into().unwrap();
        let ctx = Context {
            owner_id: hex(fields[2]),
            doc_id: hex(fields[3]).try_into().unwrap(),
            item_id: hex(fields[4]).try_into().unwrap(),
            key_version: fields[5].parse().unwrap(),
            format_version: 0,
        };
        let payload = hex(fields[6]);
        let expected = hex(fields[9]);
        assert_eq!(envelope::aad(&ctx).unwrap(), hex(fields[7]));
        assert_eq!(framing::encode(&payload).unwrap(), hex(fields[8]));
        assert_eq!(
            envelope::seal_with_nonce(&key, &nonce, &ctx, &payload).unwrap(),
            expected
        );
        assert_eq!(envelope::open(&key, &ctx, &expected).unwrap(), payload);
    }
}

#[cfg_attr(test, test)]
pub fn published_xchacha_vector() {
    // draft-irtf-cfrg-xchacha appendix A.1, also RustCrypto 0.11.0 tests/lib.rs.
    let key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
    let nonce: [u8; 24] = std::array::from_fn(|i| 0x40 + i as u8);
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213",
        "b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565",
        "d3fff921f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49"
    ));
    let cipher = XChaCha20Poly1305::new((&key).into());
    assert_eq!(
        cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad
                }
            )
            .unwrap(),
        expected
    );
    assert_eq!(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &expected,
                    aad: &aad
                }
            )
            .unwrap(),
        plaintext
    );
}

#[cfg_attr(test, test)]
pub fn envelope_roundtrip_and_context_bytes() {
    let ctx = context();
    let mut expected = b"privatale-prototype/PTE0\0\x0f\0\0\0synthetic-owner".to_vec();
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&[3; 16]);
    expected.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(envelope::aad(&ctx).unwrap(), expected);
    for (i, len) in [0, 5, 244, 245, 501, framing::MAX_PAYLOAD_LEN]
        .into_iter()
        .enumerate()
    {
        let payload = vec![0x80; len];
        let nonce = [i as u8; 24]; // само синтетичен fixture; уникален за всеки случай.
        let sealed = envelope::seal_with_nonce(&[1; 32], &nonce, &ctx, &payload).unwrap();
        assert_eq!(sealed.len(), framing::encode(&payload).unwrap().len() + 44);
        assert_eq!(envelope::open(&[1; 32], &ctx, &sealed).unwrap(), payload);
    }
}

#[cfg_attr(test, test)]
pub fn envelope_rejects_mutations_and_wrong_context() {
    let ctx = context();
    let sealed = envelope::seal_with_nonce(&[1; 32], &[9; 24], &ctx, b"synthetic").unwrap();
    assert_eq!(
        envelope::open(&[2; 32], &ctx, &sealed),
        Err(Error::Authentication)
    );
    for offset in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[offset] ^= 1;
        assert!(
            envelope::open(&[1; 32], &ctx, &changed).is_err(),
            "offset {offset}"
        );
    }
    for len in 0..sealed.len() {
        assert!(envelope::open(&[1; 32], &ctx, &sealed[..len]).is_err());
    }
    let mut extra = sealed.clone();
    extra.push(0);
    assert!(envelope::open(&[1; 32], &ctx, &extra).is_err());
    for field in 0..5 {
        let mut other = ctx.clone();
        match field {
            0 => other.owner_id[0] ^= 1,
            1 => other.doc_id[0] ^= 1,
            2 => other.item_id[0] ^= 1,
            3 => other.key_version += 1,
            _ => other.format_version += 1,
        }
        assert!(envelope::open(&[1; 32], &other, &sealed).is_err());
    }
    let mut invalid = ctx.clone();
    invalid.owner_id.clear();
    assert_eq!(envelope::aad(&invalid), Err(Error::InvalidContext));
    invalid.owner_id = vec![0; 1025];
    assert_eq!(envelope::aad(&invalid), Err(Error::InvalidContext));
}

#[cfg_attr(test, test)]
pub fn authenticated_invalid_frame_is_rejected() {
    let ctx = context();
    let key = [1; 32];
    let nonce = [10; 24];
    let aad = envelope::aad(&ctx).unwrap();
    let mut frame = framing::encode(b"synthetic").unwrap();
    *frame.last_mut().unwrap() = 1;
    let ciphertext = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &frame,
                aad: &aad,
            },
        )
        .unwrap();
    let mut sealed = b"PTE0".to_vec();
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    assert_eq!(
        envelope::open(&key, &ctx, &sealed),
        Err(Error::Frame(framing::FrameError::InvalidPadding))
    );
    // Повреден tag не стига до parser-а, дори plaintext-ът вече е невалиден.
    *sealed.last_mut().unwrap() ^= 1;
    assert_eq!(
        envelope::open(&key, &ctx, &sealed),
        Err(Error::Authentication)
    );
}
