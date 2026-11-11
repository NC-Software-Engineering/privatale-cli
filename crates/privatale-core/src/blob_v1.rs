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
//! Bounded 64 KiB record crypto. Authenticated prefixes are NOT a complete file.
//! Sync callers must wait for finish before applying anything; no apply/storage API.
use crate::{
    amk_v1::hkdf_key,
    padded_len,
    sync_item_v1::{self, Error},
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;
pub const CHUNK: usize = 65536;
pub const MAX_BODY: u64 = 5_000_000_000;
pub const MAX_PADDED: u64 = 5_033_164_800;
pub const MAX_CIPHERTEXT: u64 = 5_036_236_845;
#[derive(Clone, Debug)]
pub enum Context {
    Media {
        owner_id: [u8; 16],
        doc_id: [u8; 16],
        blob_id: [u8; 16],
        format_version: u32,
    },
    Sync {
        item: sync_item_v1::Context,
        blob_id: [u8; 16],
    },
}
impl Context {
    pub fn class(&self) -> u8 {
        match self {
            Self::Media { .. } => 1,
            Self::Sync { .. } => 2,
        }
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::Media {
                owner_id,
                doc_id,
                blob_id,
                format_version,
            } => {
                if *format_version != 1 {
                    return Err(Error::InvalidContext);
                }
                let mut b = owner_id.to_vec();
                b.extend(doc_id);
                b.extend(blob_id);
                b.extend(format_version.to_le_bytes());
                Ok(b)
            }
            Self::Sync { item, blob_id } => {
                let a = sync_item_v1::aad(item, &[0; 24])?;
                let mut b = a[b"privatale/sync-item/aad/v1\0".len()..a.len() - 28].to_vec();
                b.extend(blob_id);
                Ok(b)
            }
        }
    }
    fn magic(&self) -> &'static [u8; 4] {
        if self.class() == 1 { b"PTM1" } else { b"PTP1" }
    }
}
pub fn sizes(body: u64) -> Result<(u64, u64, u64), Error> {
    if body > MAX_BODY {
        return Err(Error::TooLarge);
    }
    let p = body
        .checked_add(12)
        .and_then(padded_len)
        .ok_or(Error::TooLarge)?;
    let (count, c) = wire_size(p)?;
    Ok((p, count, c))
}
fn wire_size(p: u64) -> Result<(u64, u64), Error> {
    if !(256..=MAX_PADDED).contains(&p) || padded_len(p) != Some(p) {
        return Err(Error::TooLarge);
    }
    let n = p.checked_add(CHUNK as u64 - 1).ok_or(Error::TooLarge)? / CHUNK as u64;
    let c = p
        .checked_add(n.checked_mul(40).ok_or(Error::TooLarge)?)
        .and_then(|v| v.checked_add(45))
        .ok_or(Error::TooLarge)?;
    if c > MAX_CIPHERTEXT {
        return Err(Error::TooLarge);
    }
    Ok((n, c))
}
struct State {
    context: Context,
    header: [u8; 45],
    key: Zeroizing<[u8; 32]>,
    p: u64,
    count: u64,
    index: u64,
    body: Option<u64>,
    poisoned: bool,
    finished: bool,
}
impl State {
    fn new(context: Context, base: &[u8; 32], h: [u8; 45]) -> Result<Self, Error> {
        if &h[..4] != b"PTB1" || h[4] != context.class() {
            return Err(Error::InvalidEnvelope);
        }
        let p = u64::from_le_bytes(h[37..45].try_into().unwrap());
        let (count, _) = wire_size(p)?;
        let mut info = b"privatale/blob/key/v1\0".to_vec();
        info.push(context.class());
        info.extend(context.bytes()?);
        let key = hkdf_key(base, Some(&h[5..37]), &info);
        Ok(Self {
            context,
            header: h,
            key,
            p,
            count,
            index: 0,
            body: None,
            poisoned: false,
            finished: false,
        })
    }
    fn active(&self) -> Result<(), Error> {
        if self.poisoned || self.finished || self.index >= self.count {
            Err(Error::InvalidFrame)
        } else {
            Ok(())
        }
    }
    fn length(&self) -> usize {
        (self.p - self.index * CHUNK as u64).min(CHUNK as u64) as usize
    }
    fn aad(&self) -> Result<Vec<u8>, Error> {
        let mut a = b"privatale/blob/chunk/aad/v1\0".to_vec();
        a.extend(self.context.bytes()?);
        a.extend(self.header);
        a.extend(self.index.to_le_bytes());
        a.push(u8::from(self.index + 1 == self.count));
        a.extend((self.length() as u32).to_le_bytes());
        Ok(a)
    }
    fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn finish(&mut self) -> Result<(), Error> {
        let r = if self.poisoned || self.finished || self.index != self.count || self.body.is_none()
        {
            Err(Error::InvalidFrame)
        } else {
            self.finished = true;
            Ok(())
        };
        self.fail(r)
    }
}
pub struct Encoder {
    state: State,
}
impl Encoder {
    /// Deterministic fixture/browser entropy boundary, not a random-ID wrapper.
    pub fn fixture_new(
        context: Context,
        base: &[u8; 32],
        body: u64,
        stream_id: &[u8; 32],
    ) -> Result<Self, Error> {
        let (p, _, _) = sizes(body)?;
        let mut h = [0; 45];
        h[..4].copy_from_slice(b"PTB1");
        h[4] = context.class();
        h[5..37].copy_from_slice(stream_id);
        h[37..].copy_from_slice(&p.to_le_bytes());
        let mut state = State::new(context, base, h)?;
        state.body = Some(body);
        Ok(Self { state })
    }
    #[cfg(target_os = "linux")]
    pub fn new(context: Context, base: &[u8; 32], body: u64) -> Result<Self, Error> {
        context.bytes()?;
        sizes(body)?;
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| Error::EntropyUnavailable)?;
        Self::fixture_new(context, base, body, &id)
    }
    pub fn header(&self) -> [u8; 45] {
        self.state.header
    }
    /// Exact body bytes required for the next record (padding is generated internally).
    pub fn next_body_len(&self) -> Result<usize, Error> {
        self.state.active()?;
        let start = self.state.index * CHUNK as u64;
        let end = (start + self.state.length() as u64).min(12 + self.state.body.unwrap());
        Ok(end.saturating_sub(start.max(12)) as usize)
    }
    pub fn fixture_next(&mut self, body: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, Error> {
        let r = self.encode(body, nonce);
        self.state.fail(r)
    }
    fn encode(&mut self, body: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, Error> {
        self.state.active()?;
        if body.len() != self.next_body_len()? {
            return Err(Error::InvalidFrame);
        }
        let mut p = Zeroizing::new(vec![0; self.state.length()]);
        let offset = if self.state.index == 0 {
            p[..4].copy_from_slice(self.state.context.magic());
            p[4..12].copy_from_slice(&self.state.body.unwrap().to_le_bytes());
            12
        } else {
            0
        };
        p[offset..offset + body.len()].copy_from_slice(body);
        let a = self.state.aad()?;
        let ct = XChaCha20Poly1305::new((&*self.state.key).into())
            .encrypt(nonce.into(), Payload { msg: &p, aad: &a })
            .map_err(|_| Error::Authentication)?;
        let mut record = nonce.to_vec();
        record.extend(ct);
        self.state.index += 1;
        Ok(record)
    }
    #[cfg(target_os = "linux")]
    pub fn next(&mut self, body: &[u8]) -> Result<Vec<u8>, Error> {
        self.next_with_entropy(body, &mut |n| {
            getrandom::fill(n).map_err(|_| Error::EntropyUnavailable)
        })
    }
    #[cfg(any(target_os = "linux", test))]
    fn next_with_entropy(
        &mut self,
        body: &[u8],
        fill: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = Zeroizing::new([0; 24]);
        if let Err(e) = fill(nonce.as_mut()) {
            self.state.poisoned = true;
            return Err(e);
        }
        self.fixture_next(body, &nonce)
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        self.state.finish()
    }
}
pub struct Reader {
    state: State,
}
impl Reader {
    /// Header is an exact bounded slice; no untrusted P-sized allocation.
    pub fn new(context: Context, base: &[u8; 32], header: &[u8]) -> Result<Self, Error> {
        let h: [u8; 45] = header.try_into().map_err(|_| Error::InvalidEnvelope)?;
        Ok(Self {
            state: State::new(context, base, h)?,
        })
    }
    /// Returns an authenticated BODY PREFIX, never a completion indication.
    pub fn authenticated_prefix(&mut self, record: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let r = self.decode(record);
        self.state.fail(r)
    }
    fn decode(&mut self, record: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.state.active()?;
        if record.len() != 24 + self.state.length() + 16 {
            return Err(Error::InvalidEnvelope);
        }
        let a = self.state.aad()?;
        let p = Zeroizing::new(
            XChaCha20Poly1305::new((&*self.state.key).into())
                .decrypt(
                    <&[u8; 24]>::try_from(&record[..24]).unwrap().into(),
                    Payload {
                        msg: &record[24..],
                        aad: &a,
                    },
                )
                .map_err(|_| Error::Authentication)?,
        );
        if self.state.index == 0 {
            if &p[..4] != self.state.context.magic() {
                return Err(Error::InvalidFrame);
            }
            let body = u64::from_le_bytes(p[4..12].try_into().unwrap());
            if sizes(body)?.0 != self.state.p {
                return Err(Error::InvalidFrame);
            }
            self.state.body = Some(body);
        }
        let start = self.state.index * CHUNK as u64;
        let body_end = 12 + self.state.body.ok_or(Error::InvalidFrame)?;
        let offset = if start == 0 { 12 } else { 0 };
        let end = body_end.saturating_sub(start).min(p.len() as u64) as usize;
        if p[end.max(offset)..].iter().any(|b| *b != 0) {
            return Err(Error::InvalidFrame);
        }
        let prefix = Zeroizing::new(p[offset..end.max(offset)].to_vec());
        self.state.index += 1;
        Ok(prefix)
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        self.state.finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_failure_poison() {
        let c = Context::Media {
            owner_id: [1; 16],
            doc_id: [2; 16],
            blob_id: [3; 16],
            format_version: 1,
        };
        for partial in [false, true] {
            let mut e = Encoder::fixture_new(c.clone(), &[1; 32], 0, &[3; 32]).unwrap();
            assert!(
                e.next_with_entropy(&[], &mut |n| {
                    if partial {
                        n[0] = 1;
                    }
                    Err(Error::EntropyUnavailable)
                })
                .is_err()
            );
            assert!(e.fixture_next(&[], &[1; 24]).is_err());
            assert!(e.finish().is_err());
        }
    }
}
