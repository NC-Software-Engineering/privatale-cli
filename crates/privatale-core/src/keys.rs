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
//! Временен HKDF профил, одобрен само за синтетичния P1 прототип.
//! Не е продуктов key schedule, password KDF или управление на ключове.
//! AMK е 32 случайни байта в бъдещ клиент; тук се подава от caller-а.
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Точни info bytes: ASCII domain с NUL + docId (16 bytes) + keyVersion (u32 LE).
/// Няма неявна Unicode нормализация, salt, ownerId или itemId.
pub fn document_key_info(doc_id: &[u8; 16], key_version: u32) -> Vec<u8> {
    let mut info = b"privatale-prototype/document-key/HKDF-SHA256/v0\0".to_vec();
    info.extend_from_slice(doc_id);
    info.extend_from_slice(&key_version.to_le_bytes());
    info
}

/// HKDF-SHA-256 extract-and-expand (не expand-only), без salt, изход 32 bytes.
/// Version обозначава подадения AMK, не извлича стар/нов AMK от хранилище.
/// Изходът се изчиства при Drop; входният AMK е caller-owned. Това не доказва
/// изчистване на всички временни HKDF/HMAC копия, регистри или WASM памет.
pub fn derive_document_key(
    amk: &[u8; 32],
    doc_id: &[u8; 16],
    key_version: u32,
) -> Zeroizing<[u8; 32]> {
    let info = document_key_info(doc_id, key_version);
    let mut output = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, amk)
        .expand(&info, output.as_mut())
        .expect("32-byte output is below HKDF-SHA-256's fixed 8160-byte limit");
    output
}
