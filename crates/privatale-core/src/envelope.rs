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
//! Само синтетичен P1 експеримент, не продуктов formatVersion 1.
//! PTE0 | nonce(24) | AEAD(PTP0 frame) | tag(16).
//! Модулът приема готов ключ: не извиква HKDF и не управлява ключове/nonce.
//! Временният HKDF експеримент е отделен в crate::keys.
//! Подаденият nonce ТРЯБВА да е уникален за ключа; API не налага това.
use crate::{framing, padded_len};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};

use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"PTE0";
const PREFIX: usize = 28;
const TAG: usize = 16;

#[derive(Clone, Debug)]
pub struct Context {
    /// Непрозрачни bytes, не Unicode нормализация или проверка на акаунт.
    pub owner_id: Vec<u8>,
    pub doc_id: [u8; 16],
    pub item_id: [u8; 16],
    pub key_version: u32,
    pub format_version: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidContext,
    InvalidEnvelope,
    Authentication,
    Frame(framing::FrameError),
}

/// Domain separator + length-prefixed owner + фиксирани IDs и LE версии.
/// Версия 0 е единствената версия на временния прототип.
pub fn aad(context: &Context) -> Result<Vec<u8>, Error> {
    if context.owner_id.is_empty() || context.owner_id.len() > 1024 || context.format_version != 0 {
        return Err(Error::InvalidContext);
    }
    let mut bytes = b"privatale-prototype/PTE0\0".to_vec();
    bytes.extend_from_slice(&(context.owner_id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&context.owner_id);
    bytes.extend_from_slice(&context.doc_id);
    bytes.extend_from_slice(&context.item_id);
    bytes.extend_from_slice(&context.key_version.to_le_bytes());
    bytes.extend_from_slice(&context.format_version.to_le_bytes());
    Ok(bytes)
}

/// Само за синтетични вектори с изрично подаден nonce, не клиентски encrypt API.
pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; 24],
    context: &Context,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = aad(context)?;
    let frame = Zeroizing::new(framing::encode(payload).map_err(Error::Frame)?);
    let encrypted = XChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: &frame,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut output = MAGIC.to_vec();
    output.extend_from_slice(nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

/// AEAD проверката е ПРЕДИ plaintext parser-а; при грешка не се връща plaintext.
pub fn open(key: &[u8; 32], context: &Context, envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let maximum =
        padded_len((12 + framing::MAX_PAYLOAD_LEN) as u64).unwrap() as usize + PREFIX + TAG;
    if envelope.len() < PREFIX + 256 + TAG || envelope.len() > maximum || &envelope[..4] != MAGIC {
        return Err(Error::InvalidEnvelope);
    }
    let aad = aad(context)?;
    let nonce: &[u8; 24] = envelope[4..PREFIX].try_into().unwrap();
    let frame = XChaCha20Poly1305::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: &envelope[PREFIX..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let frame = Zeroizing::new(frame);
    // Върнатият plaintext и входните key/payload са собственост на caller-а.
    Ok(framing::decode(&frame).map_err(Error::Frame)?.to_vec())
}
