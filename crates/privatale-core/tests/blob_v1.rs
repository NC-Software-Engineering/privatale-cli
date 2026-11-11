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
    blob_v1::{self as b, Context, Encoder, Reader},
    sync_item_v1::{self as s, Kind},
};
fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn media() -> Context {
    Context::Media {
        owner_id: [1; 16],
        doc_id: [2; 16],
        blob_id: [3; 16],
        format_version: 1,
    }
}
fn ctx(cls: u8, v: &[u8]) -> Context {
    if cls == 1 {
        Context::Media {
            owner_id: v[..16].try_into().unwrap(),
            doc_id: v[16..32].try_into().unwrap(),
            blob_id: v[32..48].try_into().unwrap(),
            format_version: u32::from_le_bytes(v[48..52].try_into().unwrap()),
        }
    } else {
        Context::Sync {
            item: s::Context {
                owner_id: v[..16].try_into().unwrap(),
                doc_id: v[16..32].try_into().unwrap(),
                item_id: v[32..48].try_into().unwrap(),
                key_version: 1,
                kind: Kind::Snapshot,
                epoch: 0x0102030405060708,
                device_id: v[65..81].try_into().unwrap(),
                covers_up_to_seq: Some(7),
            },
            blob_id: v[90..106].try_into().unwrap(),
        }
    }
}
#[cfg_attr(test, test)]
pub fn blob_full_vectors() {
    let mut count = 0;
    for row in include_str!("../../../test-vectors/blob-v1.csv")
        .lines()
        .skip(1)
    {
        let f: Vec<_> = row.split(',').collect();
        assert_eq!(f.len(), 10);
        let cls = f[0].parse().unwrap();
        let len = f[1].parse().unwrap();
        let base = hex(f[2]).try_into().unwrap();
        let c = ctx(cls, &hex(f[3]));
        assert_eq!(c.bytes().unwrap(), hex(f[3]));
        let stream = hex(f[4]).try_into().unwrap();
        let body = hex(f[5]);
        let mut e = Encoder::fixture_new(c.clone(), &base, len, &stream).unwrap();
        assert_eq!(e.header().as_slice(), hex(f[7]));
        let mut r = Reader::new(c.clone(), &base, &e.header()).unwrap();
        let records: Vec<_> = f[9].split(';').map(hex).collect();
        let mut offset = 0;
        let mut opened = Vec::new();
        for record in records {
            let size = e.next_body_len().unwrap();
            let actual = e
                .fixture_next(
                    &body[offset..offset + size],
                    record[..24].try_into().unwrap(),
                )
                .unwrap();
            assert_eq!(actual, record);
            let prefix = r.authenticated_prefix(&record).unwrap();
            assert!(prefix.len() <= b::CHUNK);
            opened.extend_from_slice(&prefix);
            offset += size;
        }
        e.finish().unwrap();
        r.finish().unwrap();
        assert_eq!(opened, body);
        assert!(e.finish().is_err());
        assert!(r.finish().is_err());
        count += 1;
    }
    assert_eq!(count, 14);
}
#[cfg_attr(test, test)]
pub fn blob_boundaries_and_poison() {
    assert_eq!(
        b::sizes(5_000_000_000).unwrap(),
        (5_033_164_800, 76800, 5_036_236_845)
    );
    for n in [5_000_000_001, u64::MAX] {
        assert!(b::sizes(n).is_err());
    }
    let mut seed = 1u64;
    for _ in 0..1000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = seed % 5_000_000_001;
        let (p, k, c) = b::sizes(n).unwrap();
        assert!(p >= n + 12);
        assert_eq!(k, p.div_ceil(65536));
        assert_eq!(c, 45 + p + k * 40);
        assert!(c <= b::MAX_CIPHERTEXT);
    }
    let base = [9; 32];
    let c = media();
    let mut e = Encoder::fixture_new(c.clone(), &base, 131061, &[1; 32]).unwrap();
    let header = e.header();
    let mut records = Vec::new();
    while let Ok(n) = e.next_body_len() {
        records.push(
            e.fixture_next(&vec![7; n], &[records.len() as u8; 24])
                .unwrap(),
        );
    }
    e.finish().unwrap();
    assert!(e.fixture_next(&[], &[0; 24]).is_err());
    for order in [
        vec![1, 0, 2],
        vec![0, 0, 2],
        vec![0, 2, 1],
        vec![0, 1],
        vec![],
    ] {
        let mut r = Reader::new(c.clone(), &base, &header).unwrap();
        let mut failed = false;
        for i in order {
            if r.authenticated_prefix(&records[i]).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed || r.finish().is_err());
        assert!(r.finish().is_err());
        assert!(r.authenticated_prefix(&records[0]).is_err());
    }
    for i in [0, 24, records[0].len() - 1] {
        let mut bad = records[0].clone();
        bad[i] ^= 1;
        let mut r = Reader::new(c.clone(), &base, &header).unwrap();
        assert!(r.authenticated_prefix(&bad).is_err());
        assert!(r.authenticated_prefix(&records[0]).is_err());
        assert!(r.finish().is_err());
    }
    for cut in [0, 1, 23, 24, records[0].len() - 1, records[0].len() + 1] {
        let mut bad = records[0].clone();
        bad.resize(cut, 0);
        let mut r = Reader::new(c.clone(), &base, &header).unwrap();
        assert!(r.authenticated_prefix(&bad).is_err());
        assert!(r.finish().is_err());
    }
    for i in 0..45 {
        let mut h = header;
        h[i] ^= 1;
        if let Ok(mut r) = Reader::new(c.clone(), &base, &h) {
            assert!(r.authenticated_prefix(&records[0]).is_err());
            assert!(r.finish().is_err());
        }
    }
    let mut r = Reader::new(c.clone(), &[8; 32], &header).unwrap();
    assert!(r.authenticated_prefix(&records[0]).is_err());
    let mut other = media();
    if let Context::Media { blob_id, .. } = &mut other {
        blob_id[0] ^= 1;
    }
    let mut r = Reader::new(other, &base, &header).unwrap();
    assert!(r.authenticated_prefix(&records[0]).is_err());
    let mut r = Reader::new(c.clone(), &base, &header).unwrap();
    for record in &records {
        r.authenticated_prefix(record).unwrap();
    }
    assert!(r.authenticated_prefix(&records[0]).is_err());
    assert!(r.finish().is_err());
    let mut e = Encoder::fixture_new(c.clone(), &base, 0, &[1; 32]).unwrap();
    assert!(e.fixture_next(&[1], &[1; 24]).is_err());
    assert!(e.fixture_next(&[], &[1; 24]).is_err());
    assert!(e.finish().is_err());
}
#[cfg_attr(test, test)]
pub fn blob_authenticated_invalid_frames() {
    let row = include_str!("../../../test-vectors/blob-v1.csv")
        .lines()
        .nth(1)
        .unwrap();
    let f: Vec<_> = row.split(',').collect();
    let c = ctx(1, &hex(f[3]));
    let base = hex(f[2]).try_into().unwrap();
    let key: [u8; 32] = hex(f[6]).try_into().unwrap();
    let h = hex(f[7]);
    let aad = hex(f[8]);
    let record = hex(f[9]);
    let nonce: &[u8; 24] = record[..24].try_into().unwrap();
    for mode in 0..5 {
        let mut frame = vec![0; 256];
        frame[..4].copy_from_slice(b"PTM1");
        match mode {
            0 => frame[0] = 0,
            1 => frame[255] = 1,
            2 => frame[4..12].copy_from_slice(&245u64.to_le_bytes()),
            3 => frame[4..12].copy_from_slice(&5_000_000_001u64.to_le_bytes()),
            _ => frame[4..12].copy_from_slice(&u64::MAX.to_le_bytes()),
        };
        let ct = XChaCha20Poly1305::new((&key).into())
            .encrypt(
                nonce.into(),
                Payload {
                    msg: &frame,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut bad = nonce.to_vec();
        bad.extend(ct);
        let mut r = Reader::new(c.clone(), &base, &h).unwrap();
        assert!(r.authenticated_prefix(&bad).is_err());
        assert!(r.finish().is_err());
    }
    // Valid auth but non-minimal whole-file bucket: 272 bytes for an empty body.
    let mut h = h;
    h[37..45].copy_from_slice(&272u64.to_le_bytes());
    let mut aad = aad;
    let pos = b"privatale/blob/chunk/aad/v1\0".len() + c.bytes().unwrap().len();
    aad[pos..pos + 45].copy_from_slice(&h);
    let end = aad.len();
    aad[end - 4..].copy_from_slice(&272u32.to_le_bytes());
    let mut p = vec![0; 272];
    p[..4].copy_from_slice(b"PTM1");
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(nonce.into(), Payload { msg: &p, aad: &aad })
        .unwrap();
    let mut bad = nonce.to_vec();
    bad.extend(ct);
    let mut r = Reader::new(c, &base, &h).unwrap();
    assert!(r.authenticated_prefix(&bad).is_err());
    assert!(r.finish().is_err());
}

#[cfg_attr(test, test)]
pub fn blob_late_padding_and_mixed_streams() {
    for row in include_str!("../../../test-vectors/blob-v1.csv")
        .lines()
        .skip(1)
    {
        let f: Vec<_> = row.split(',').collect();
        if f[1] != "131061" {
            continue;
        }
        let cls = f[0].parse().unwrap();
        let context = ctx(cls, &hex(f[3]));
        let base = hex(f[2]).try_into().unwrap();
        let key: [u8; 32] = hex(f[6]).try_into().unwrap();
        let header = hex(f[7]);
        let aads: Vec<_> = f[8].split(';').map(hex).collect();
        let records: Vec<_> = f[9].split(';').map(hex).collect();
        let mut r = Reader::new(context.clone(), &base, &header).unwrap();
        for record in &records[..records.len() - 1] {
            assert!(!r.authenticated_prefix(record).unwrap().is_empty());
        }
        let last = records.last().unwrap();
        let nonce: &[u8; 24] = last[..24].try_into().unwrap();
        let aad = aads.last().unwrap();
        let cipher = XChaCha20Poly1305::new((&key).into());
        let mut p = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: &last[24..],
                    aad,
                },
            )
            .unwrap();
        *p.last_mut().unwrap() = 1;
        let ct = cipher
            .encrypt(nonce.into(), Payload { msg: &p, aad })
            .unwrap();
        let mut bad = nonce.to_vec();
        bad.extend(ct);
        assert!(r.authenticated_prefix(&bad).is_err());
        assert!(r.finish().is_err());
        assert!(r.authenticated_prefix(last).is_err());
        let mut other = Encoder::fixture_new(context.clone(), &base, 131061, &[99; 32]).unwrap();
        let n = other.next_body_len().unwrap();
        let record = other.fixture_next(&vec![0; n], &[0; 24]).unwrap();
        let mut r = Reader::new(context, &base, &header).unwrap();
        assert!(r.authenticated_prefix(&record).is_err());
        assert!(r.finish().is_err());
    }
}
