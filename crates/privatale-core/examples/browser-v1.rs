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
//! Separate pointer-free P1 synthetic browser ABI. No memory addresses are exposed.
//! JS supplies Web Crypto bytes only after its type/resource validation.
use privatale_core::{amk_v1 as a, blob_v1 as b, sync_item_v1 as s};
use std::cell::RefCell;
use zeroize::{Zeroize, Zeroizing};
#[derive(Default)]
struct Bridge {
    fields: [Zeroizing<Vec<u8>>; 5],
    out: Zeroizing<Vec<u8>>,
    encoder: Option<b::Encoder>,
    reader: Option<b::Reader>,
}
thread_local! {static BRIDGE:RefCell<Bridge>=RefCell::new(Bridge::default());}
fn u32at(b: &[u8], i: usize) -> Result<u32, s::Error> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or(s::Error::InvalidContext)?
            .try_into()
            .unwrap(),
    ))
}
fn u64at(b: &[u8], i: usize) -> Result<u64, s::Error> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8)
            .ok_or(s::Error::InvalidContext)?
            .try_into()
            .unwrap(),
    ))
}
fn arr<const N: usize>(b: &[u8]) -> Result<&[u8; N], s::Error> {
    b.try_into().map_err(|_| s::Error::InvalidContext)
}
fn sync(b: &[u8]) -> Result<s::Context, s::Error> {
    if b.len() != 90 || u32at(b, 52)? != 1 {
        return Err(s::Error::InvalidContext);
    }
    let coverage = u64at(b, 82)?;
    let present = b[81];
    if present > 1 || (present == 0 && coverage != 0) {
        return Err(s::Error::InvalidContext);
    }
    let c = s::Context {
        owner_id: *arr(&b[..16])?,
        doc_id: *arr(&b[16..32])?,
        item_id: *arr(&b[32..48])?,
        key_version: u32at(b, 48)?,
        kind: s::Kind::try_from(b[56])?,
        epoch: u64at(b, 57)?,
        device_id: *arr(&b[65..81])?,
        covers_up_to_seq: if present == 1 { Some(coverage) } else { None },
    };
    s::aad(&c, &[0; 24])?;
    Ok(c)
}
fn amk(b: &[u8]) -> Result<a::Context, s::Error> {
    if b.len() != 40 {
        return Err(s::Error::InvalidContext);
    }
    let c = a::Context {
        owner_id: *arr(&b[..16])?,
        envelope_id: *arr(&b[16..32])?,
        amk_version: u32at(b, 32)?,
        format_version: u32at(b, 36)?,
    };
    c.bytes()?;
    Ok(c)
}
fn blob(b: &[u8]) -> Result<b::Context, s::Error> {
    match b.len() {
        52 => Ok(b::Context::Media {
            owner_id: *arr(&b[..16])?,
            doc_id: *arr(&b[16..32])?,
            blob_id: *arr(&b[32..48])?,
            format_version: u32at(b, 48)?,
        }),
        106 => Ok(b::Context::Sync {
            item: sync(&b[..90])?,
            blob_id: *arr(&b[90..])?,
        }),
        _ => Err(s::Error::InvalidContext),
    }
}
impl Bridge {
    fn run(&mut self, op: u32, arg: u64) -> Result<Vec<u8>, s::Error> {
        let [key, c, extra, data, entropy] = &self.fields;
        match op {
            1 => s::seal_with_nonce(arr(key)?, &sync(c)?, arr(entropy)?, data),
            2 => s::open(arr(key)?, &sync(c)?, data),
            3 => {
                if extra.len() != 48 {
                    return Err(s::Error::InvalidContext);
                }
                a::fixture_device_seal(
                    &amk(c)?,
                    arr(&extra[..16])?,
                    arr(&extra[16..])?,
                    arr(data)?,
                    arr(entropy)?,
                )
            }
            4 => Ok(a::device_open(&amk(c)?, arr(extra)?, arr(key)?, data)?.to_vec()),
            5 => a::fixture_recovery_seal(&amk(c)?, arr(key)?, arr(data)?, arr(entropy)?),
            6 => Ok(a::recovery_open(&amk(c)?, arr(key)?, data)?.to_vec()),
            7 => {
                if entropy.len() != 40 {
                    return Err(s::Error::InvalidContext);
                }
                a::fixture_password_seal(
                    &amk(c)?,
                    key,
                    arr(data)?,
                    arr(&entropy[..16])?,
                    arr(&entropy[16..])?,
                    u32::try_from(arg).map_err(|_| s::Error::InvalidContext)?,
                )
            }
            8 => Ok(a::password_open(&amk(c)?, key, data)?.to_vec()),
            9 | 12 => {
                if self.encoder.is_some() || self.reader.is_some() {
                    return Err(s::Error::InvalidFrame);
                }
                let context = blob(c)?;
                let base = match &context {
                    b::Context::Media { .. } => Zeroizing::new(*arr::<32>(key)?),
                    b::Context::Sync { item, .. } => {
                        s::derive_document_key(arr(key)?, &item.doc_id, item.key_version)?
                    }
                };
                if op == 9 {
                    let encoder = b::Encoder::fixture_new(context, &base, arg, arr(entropy)?)?;
                    let h = encoder.header().to_vec();
                    self.encoder = Some(encoder);
                    Ok(h)
                } else {
                    self.reader = Some(b::Reader::new(context, &base, data)?);
                    Ok(vec![])
                }
            }
            10 => self
                .encoder
                .as_mut()
                .ok_or(s::Error::InvalidFrame)?
                .fixture_next(data, arr(entropy)?),
            11 => {
                self.encoder
                    .as_mut()
                    .ok_or(s::Error::InvalidFrame)?
                    .finish()?;
                self.encoder = None;
                Ok(vec![])
            }
            13 => Ok(self
                .reader
                .as_mut()
                .ok_or(s::Error::InvalidFrame)?
                .authenticated_prefix(data)?
                .to_vec()),
            14 => {
                self.reader
                    .as_mut()
                    .ok_or(s::Error::InvalidFrame)?
                    .finish()?;
                self.reader = None;
                Ok(vec![])
            }
            _ => Err(s::Error::InvalidContext),
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_abort() {
    BRIDGE.with(|b| *b.borrow_mut() = Bridge::default());
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_clear() {
    BRIDGE.with(|b| {
        let mut b = b.borrow_mut();
        for f in &mut b.fields {
            f.zeroize();
        }
        b.out.zeroize();
    });
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_push(field: u32, byte: u32) -> u32 {
    BRIDGE.with(|b| {
        let mut b = b.borrow_mut();
        let cap = match field {
            0 => 1024,
            1 => 106,
            2 => 48,
            3 => s::MAX_INLINE,
            4 => 40,
            _ => 0,
        };
        if byte > 255 || field > 4 || b.fields[field as usize].len() >= cap {
            *b = Bridge::default();
            return 0;
        }
        b.fields[field as usize].push(byte as u8);
        1
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_run(op: u32, arg: u64) -> u32 {
    BRIDGE.with(|b| {
        let mut b = b.borrow_mut();
        b.out.zeroize();
        let result = b.run(op, arg);
        for f in &mut b.fields {
            f.zeroize();
        }
        match result {
            Ok(out) => {
                b.out = Zeroizing::new(out);
                1
            }
            Err(_) => {
                *b = Bridge::default();
                0
            }
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_len() -> u32 {
    BRIDGE.with(|b| b.borrow().out.len() as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn v1_byte(index: u32) -> u32 {
    BRIDGE.with(|b| {
        b.borrow()
            .out
            .get(index as usize)
            .map_or(256, |v| *v as u32)
    })
}
