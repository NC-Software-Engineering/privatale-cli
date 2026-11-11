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
use privatale_core::sync_item_v1::{self as v1, Context, Error, Kind};

fn hex(value: &str) -> Vec<u8> {
    let (pairs, rest) = value.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn context() -> Context {
    Context {
        owner_id: std::array::from_fn(|i| i as u8),
        doc_id: [2; 16],
        item_id: [3; 16],
        device_id: [4; 16],
        key_version: 1,
        kind: Kind::Snapshot,
        epoch: 7,
        covers_up_to_seq: Some(42),
    }
}

#[cfg_attr(test, test)]
pub fn v1_golden_vectors() {
    let rows: Vec<_> = include_str!("../../../test-vectors/sync-item-v1.csv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let f: Vec<_> = row.split(',').collect();
        assert_eq!(f.len(), 16);
        let amk: [u8; 32] = hex(f[0]).try_into().unwrap();
        let ctx = Context {
            owner_id: hex(f[1]).try_into().unwrap(),
            doc_id: hex(f[2]).try_into().unwrap(),
            item_id: hex(f[3]).try_into().unwrap(),
            device_id: hex(f[4]).try_into().unwrap(),
            key_version: f[5].parse().unwrap(),
            kind: Kind::try_from(f[6].parse::<u8>().unwrap()).unwrap(),
            epoch: f[7].parse().unwrap(),
            covers_up_to_seq: if f[8].is_empty() {
                None
            } else {
                Some(f[8].parse().unwrap())
            },
        };
        let nonce: [u8; 24] = hex(f[9]).try_into().unwrap();
        let body = hex(f[10]);
        let expected = hex(f[15]);
        assert_eq!(
            v1::document_key_info(&ctx.doc_id, ctx.key_version).unwrap(),
            hex(f[11])
        );
        let key = v1::derive_document_key(&amk, &ctx.doc_id, ctx.key_version).unwrap();
        assert_eq!(key.as_slice(), hex(f[12]));
        let aad = v1::aad(&ctx, &nonce).unwrap();
        assert_eq!(aad, hex(f[13]));
        assert_eq!(
            v1::seal_with_nonce(&amk, &ctx, &nonce, &body).unwrap(),
            expected
        );
        assert_eq!(v1::open(&amk, &ctx, &expected).unwrap(), body);
        let frame = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &expected[28..],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(frame, hex(f[14]));
    }
}

#[cfg_attr(test, test)]
pub fn v1_bounds_and_context() {
    for (body, expected) in [(0, 300), (244, 300), (245, 316), (1_032_180, 1_032_236)] {
        assert_eq!(v1::inline_size(body), Ok(expected));
    }
    for length in [1_032_181, 1_048_576, u64::MAX - 11, u64::MAX] {
        assert_eq!(v1::inline_size(length), Err(Error::TooLarge));
    }
    let mut ctx = context();
    let body = vec![42; v1::MAX_BODY];
    let sealed = v1::seal_with_nonce(&[1; 32], &ctx, &[20; 24], &body).unwrap();
    assert_eq!(sealed.len(), 1_032_236);
    assert_eq!(v1::open(&[1; 32], &ctx, &sealed).unwrap(), body);
    assert_eq!(
        v1::seal_with_nonce(&[1; 32], &ctx, &[21; 24], &vec![0; v1::MAX_BODY + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        v1::open(&[1; 32], &ctx, &vec![0; v1::MAX_INLINE + 1]),
        Err(Error::InvalidEnvelope)
    );
    ctx.key_version = 0;
    assert_eq!(v1::aad(&ctx, &[0; 24]), Err(Error::InvalidContext));
    ctx.key_version = u32::MAX;
    ctx.covers_up_to_seq = Some(i64::MAX as u64);
    assert!(v1::aad(&ctx, &[0; 24]).is_ok());
    ctx.covers_up_to_seq = Some(i64::MAX as u64 + 1);
    assert_eq!(v1::aad(&ctx, &[0; 24]), Err(Error::InvalidContext));
    ctx.covers_up_to_seq = None;
    assert_eq!(v1::aad(&ctx, &[0; 24]), Err(Error::InvalidContext));
    ctx.kind = Kind::Change;
    assert!(v1::aad(&ctx, &[0; 24]).is_ok());
    ctx.covers_up_to_seq = Some(0);
    assert_eq!(v1::aad(&ctx, &[0; 24]), Err(Error::InvalidContext));
    for unknown in [0, 6, 255] {
        assert_eq!(Kind::try_from(unknown), Err(Error::InvalidContext));
    }
}

#[cfg_attr(test, test)]
pub fn v1_auth_context_and_version_refusals() {
    let ctx = context();
    let amk = [1; 32];
    let sealed = v1::seal_with_nonce(&amk, &ctx, &[22; 24], b"synthetic").unwrap();
    assert_eq!(
        v1::open(&[2; 32], &ctx, &sealed),
        Err(Error::Authentication)
    );
    for field in 0..8 {
        let mut changed = ctx.clone();
        match field {
            0 => changed.owner_id[0] ^= 1,
            1 => changed.doc_id[0] ^= 1,
            2 => changed.item_id[0] ^= 1,
            3 => changed.device_id[0] ^= 1,
            4 => changed.key_version += 1,
            5 => changed.epoch += 1,
            6 => changed.covers_up_to_seq = Some(43),
            _ => {
                changed.kind = Kind::Change;
                changed.covers_up_to_seq = None;
            }
        }
        assert_eq!(
            v1::open(&amk, &changed, &sealed),
            Err(Error::Authentication)
        );
    }
    let mut mixed_endian = ctx.clone();
    mixed_endian.owner_id[..4].reverse();
    assert_eq!(
        v1::open(&amk, &mixed_endian, &sealed),
        Err(Error::Authentication)
    );
    for offset in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[offset] ^= 1;
        assert!(v1::open(&amk, &ctx, &bad).is_err());
    }
    for length in 0..sealed.len() {
        assert!(v1::open(&amk, &ctx, &sealed[..length]).is_err());
    }
    let mut extra = sealed.clone();
    extra.push(0);
    assert!(v1::open(&amk, &ctx, &extra).is_err());
    let mut v0 = sealed;
    v0[..4].copy_from_slice(b"PTE0");
    assert_eq!(v1::open(&amk, &ctx, &v0), Err(Error::InvalidEnvelope));
    assert_ne!(
        *v1::derive_document_key(&amk, &ctx.doc_id, ctx.key_version).unwrap(),
        *privatale_core::keys::derive_document_key(&amk, &ctx.doc_id, ctx.key_version)
    );
}

#[cfg_attr(test, test)]
pub fn v1_authenticated_frame_refusals() {
    let ctx = context();
    let amk = [1; 32];
    let key = v1::derive_document_key(&amk, &ctx.doc_id, 1).unwrap();
    for case in 0..4 {
        let nonce = [30 + case; 24];
        let mut frame = vec![0; if case == 3 { 512 } else { 256 }];
        frame[..4].copy_from_slice(b"PTP1");
        match case {
            0 => frame[..4].copy_from_slice(b"PTP0"),
            1 => frame[4..12].copy_from_slice(&u64::MAX.to_le_bytes()),
            2 => *frame.last_mut().unwrap() = 1,
            _ => (),
        }
        let aad = v1::aad(&ctx, &nonce).unwrap();
        let cipher = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &frame,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut envelope = b"PTI1".to_vec();
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&cipher);
        assert_eq!(v1::open(&amk, &ctx, &envelope), Err(Error::InvalidFrame));
        *envelope.last_mut().unwrap() ^= 1;
        assert_eq!(v1::open(&amk, &ctx, &envelope), Err(Error::Authentication));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn v1_linux_seal() {
    let ctx = context();
    let amk = [1; 32];
    let a = v1::seal(&amk, &ctx, b"synthetic").unwrap();
    let b = v1::seal(&amk, &ctx, b"synthetic").unwrap();
    assert_ne!(&a[4..28], &b[4..28]);
    assert_eq!(v1::open(&amk, &ctx, &a).unwrap(), b"synthetic");
}
