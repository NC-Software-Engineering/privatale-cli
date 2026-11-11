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
use hkdf::Hkdf;
use privatale_core::{envelope, keys};
use sha2::Sha256;

fn hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[cfg_attr(test, test)]
pub fn rfc5869_sha256_vectors() {
    // RFC 5869 Appendix A.1 and A.3, published independent expectations.
    let ikm = [0x0b; 22];
    for (salt, info, expected) in [
        (
            Some(hex("000102030405060708090a0b0c")),
            hex("f0f1f2f3f4f5f6f7f8f9"),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            None,
            vec![],
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ] {
        let mut output = [0; 42];
        Hkdf::<Sha256>::new(salt.as_deref(), &ikm)
            .expand(&info, &mut output)
            .unwrap();
        assert_eq!(output.as_slice(), hex(expected));
    }
}

#[cfg_attr(test, test)]
pub fn independent_document_key_vectors() {
    let rows: Vec<_> = include_str!("../../../test-vectors/hkdf.csv")
        .lines()
        .skip(1)
        .collect();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let fields: Vec<_> = row.split(',').collect();
        assert_eq!(fields.len(), 5);
        let amk: [u8; 32] = hex(fields[0]).try_into().unwrap();
        let doc: [u8; 16] = hex(fields[1]).try_into().unwrap();
        let version = fields[2].parse().unwrap();
        assert_eq!(keys::document_key_info(&doc, version), hex(fields[3]));
        assert_eq!(
            keys::derive_document_key(&amk, &doc, version).as_slice(),
            hex(fields[4])
        );
    }
}

#[cfg_attr(test, test)]
pub fn derived_key_isolation_and_envelope() {
    let amk = [42; 32];
    let doc = [17; 16];
    let key = keys::derive_document_key(&amk, &doc, 1);
    assert_eq!(*key, *keys::derive_document_key(&amk, &doc, 1));
    let alternatives = [
        keys::derive_document_key(&[43; 32], &doc, 1),
        keys::derive_document_key(&amk, &[18; 16], 1),
        keys::derive_document_key(&amk, &doc, 2),
    ];
    let context = envelope::Context {
        owner_id: b"synthetic-kdf-owner".to_vec(),
        doc_id: doc,
        item_id: [19; 16],
        key_version: 1,
        format_version: 0,
    };
    let sealed = envelope::seal_with_nonce(&key, &[20; 24], &context, b"synthetic-only").unwrap();
    assert_eq!(
        envelope::open(&key, &context, &sealed).unwrap(),
        b"synthetic-only"
    );
    for other in alternatives {
        assert_ne!(*key, *other);
        assert_eq!(
            envelope::open(&other, &context, &sealed),
            Err(envelope::Error::Authentication)
        );
    }
    // KDF does not authorize owners: the existing AAD binding still enforces isolation.
    let mut other_owner = context.clone();
    other_owner.owner_id.push(b'2');
    assert_eq!(
        envelope::open(&key, &other_owner, &sealed),
        Err(envelope::Error::Authentication)
    );
}
