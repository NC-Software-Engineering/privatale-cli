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
//! Synthetic v1 inline-only sync-item profile (docs/protocol/crypto-v1.md). No storage or AMK lifecycle.
//! This module deliberately does not accept PTE0, media or AMK envelopes.
use crate::padded_len;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAX_INLINE: usize = 1_048_576;
pub const MAX_BODY: usize = 1_032_180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Change = 1,
    Snapshot = 2,
    Epoch = 3,
    Purge = 4,
    Embedding = 5,
}

#[derive(Clone, Debug)]
pub struct Context {
    /// All UUID fields are raw network-order bytes, never platform Guid layout.
    pub owner_id: [u8; 16],
    pub doc_id: [u8; 16],
    pub item_id: [u8; 16],
    pub device_id: [u8; 16],
    pub key_version: u32,
    pub kind: Kind,
    pub epoch: u64,
    pub covers_up_to_seq: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidContext,
    TooLarge,
    InvalidEnvelope,
    Authentication,
    InvalidFrame,
    EntropyUnavailable,
}

impl TryFrom<u8> for Kind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Change),
            2 => Ok(Self::Snapshot),
            3 => Ok(Self::Epoch),
            4 => Ok(Self::Purge),
            5 => Ok(Self::Embedding),
            _ => Err(Error::InvalidContext),
        }
    }
}

fn validate(context: &Context) -> Result<(), Error> {
    if context.key_version == 0
        || (context.kind == Kind::Snapshot) != context.covers_up_to_seq.is_some()
        || context
            .covers_up_to_seq
            .is_some_and(|n| n > i64::MAX as u64)
    {
        return Err(Error::InvalidContext);
    }
    Ok(())
}

pub fn document_key_info(doc_id: &[u8; 16], key_version: u32) -> Result<Vec<u8>, Error> {
    if key_version == 0 {
        return Err(Error::InvalidContext);
    }
    let mut info = b"privatale/document-key/hkdf-sha256/v1\0".to_vec();
    info.extend_from_slice(doc_id);
    info.extend_from_slice(&key_version.to_le_bytes());
    Ok(info)
}

/// Output is wiped on drop; no claim that every HMAC/AMK temporary is wiped.
pub fn derive_document_key(
    amk: &[u8; 32],
    doc_id: &[u8; 16],
    version: u32,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let info = document_key_info(doc_id, version)?;
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, amk)
        .expand(&info, key.as_mut())
        .expect("fixed 32-byte HKDF output");
    Ok(key)
}

pub fn aad(context: &Context, nonce: &[u8; 24]) -> Result<Vec<u8>, Error> {
    validate(context)?;
    let mut aad = b"privatale/sync-item/aad/v1\0".to_vec();
    aad.extend_from_slice(&context.owner_id);
    aad.extend_from_slice(&context.doc_id);
    aad.extend_from_slice(&context.item_id);
    aad.extend_from_slice(&context.key_version.to_le_bytes());
    aad.extend_from_slice(&1_u32.to_le_bytes());
    aad.push(context.kind as u8);
    aad.extend_from_slice(&context.epoch.to_le_bytes());
    aad.extend_from_slice(&context.device_id);
    aad.push(u8::from(context.covers_up_to_seq.is_some()));
    aad.extend_from_slice(&context.covers_up_to_seq.unwrap_or(0).to_le_bytes());
    aad.extend_from_slice(b"PTI1");
    aad.extend_from_slice(nonce);
    Ok(aad)
}

/// Returns the complete encrypted size, not the unpadded body length.
pub fn inline_size(body_len: u64) -> Result<usize, Error> {
    let padded = body_len
        .checked_add(12)
        .and_then(padded_len)
        .ok_or(Error::TooLarge)?;
    let total = padded.checked_add(44).ok_or(Error::TooLarge)?;
    if total > MAX_INLINE as u64 {
        return Err(Error::TooLarge);
    }
    Ok(total as usize)
}

/// Explicit nonce only for deterministic fixtures; callers must never reuse it with a key.
pub fn seal_with_nonce(
    amk: &[u8; 32],
    context: &Context,
    nonce: &[u8; 24],
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    let size = inline_size(body.len() as u64)?;
    let aad = aad(context, nonce)?;
    let key = derive_document_key(amk, &context.doc_id, context.key_version)?;
    let mut frame = Zeroizing::new(vec![0; size - 44]);
    frame[..4].copy_from_slice(b"PTP1");
    frame[4..12].copy_from_slice(&(body.len() as u64).to_le_bytes());
    frame[12..12 + body.len()].copy_from_slice(body);
    let encrypted = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: &frame,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut result = Vec::with_capacity(size);
    result.extend_from_slice(b"PTI1");
    result.extend_from_slice(nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

#[cfg(target_os = "linux")]
pub fn seal(amk: &[u8; 32], context: &Context, body: &[u8]) -> Result<Vec<u8>, Error> {
    validate(context)?;
    inline_size(body.len() as u64)?;
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::EntropyUnavailable)?;
    seal_with_nonce(amk, context, &nonce, body)
}

pub fn open(amk: &[u8; 32], context: &Context, envelope: &[u8]) -> Result<Vec<u8>, Error> {
    if !(300..=MAX_INLINE).contains(&envelope.len()) || &envelope[..4] != b"PTI1" {
        return Err(Error::InvalidEnvelope);
    }
    let nonce: &[u8; 24] = envelope[4..28]
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    let aad = aad(context, nonce)?;
    let key = derive_document_key(amk, &context.doc_id, context.key_version)?;
    let frame = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                nonce.into(),
                Payload {
                    msg: &envelope[28..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    if frame.len() < 12 || &frame[..4] != b"PTP1" {
        return Err(Error::InvalidFrame);
    }
    let length = u64::from_le_bytes(frame[4..12].try_into().map_err(|_| Error::InvalidFrame)?);
    // Before usize conversion/slicing, and only AFTER successful authentication.
    if inline_size(length).map_err(|_| Error::InvalidFrame)? != envelope.len() {
        return Err(Error::InvalidFrame);
    }
    let end = 12 + length as usize; // inline_size establishes a small bounded length.
    if end > frame.len() || frame[end..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidFrame);
    }
    Ok(frame[12..end].to_vec())
}
