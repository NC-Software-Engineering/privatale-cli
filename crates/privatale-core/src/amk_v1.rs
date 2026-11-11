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
//! Synthetic P1 AMK envelopes. Base HPKE does NOT authenticate a sender.
//! No enrollment, persistence, rotation or password policy is implemented here.
use crate::sync_item_v1::Error;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use sha2::Sha256;
use zeroize::Zeroizing;
type X = X25519HkdfSha256;

#[derive(Clone, Debug)]
pub struct Context {
    pub owner_id: [u8; 16],
    pub envelope_id: [u8; 16],
    pub amk_version: u32,
    pub format_version: u32,
}
impl Context {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        if self.amk_version == 0 || self.format_version != 1 {
            return Err(Error::InvalidContext);
        }
        let mut b = self.owner_id.to_vec();
        b.extend(self.envelope_id);
        b.extend(self.amk_version.to_le_bytes());
        b.extend(self.format_version.to_le_bytes());
        Ok(b)
    }
}
fn domain(name: &str, context: &Context) -> Result<Vec<u8>, Error> {
    let mut b = format!("privatale/amk/{name}/v1\0").into_bytes();
    b.extend(context.bytes()?);
    Ok(b)
}
pub fn plaintext(amk: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(vec![0; 256]);
    p[..4].copy_from_slice(b"PTA1");
    p[4..36].copy_from_slice(amk);
    p
}
fn parse(p: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if p.len() != 256 || &p[..4] != b"PTA1" || p[36..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidFrame);
    }
    Ok(Zeroizing::new(p[4..36].try_into().unwrap()))
}
pub fn hkdf_key(secret: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(salt, secret)
        .expand(info, k.as_mut())
        .expect("32 bytes");
    k
}
fn encrypt(k: &[u8; 32], nonce: &[u8; 24], aad: &[u8], amk: &[u8; 32]) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(k.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: &plaintext(amk),
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}
fn decrypt(
    k: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let p = Zeroizing::new(
        XChaCha20Poly1305::new(k.into())
            .decrypt(nonce.into(), Payload { msg: ct, aad })
            .map_err(|_| Error::Authentication)?,
    );
    parse(&p)
}
fn device_data(
    c: &Context,
    device: &[u8; 16],
    pk: &[u8; 32],
    header: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut b = domain(
        if header.is_some() {
            "device/aad"
        } else {
            "device/hpke"
        },
        c,
    )?;
    b.extend(device);
    b.extend(pk);
    if let Some(h) = header {
        b.extend(h);
    }
    Ok(b)
}
// HPKE requests exactly one 32-byte IKM. It is prefilled fallibly before entering
// the infallible library interface. No repeated bytes/PRNG fallback on exhaustion.
struct Coins {
    bytes: Zeroizing<[u8; 32]>,
    used: bool,
}
impl rand_core::TryRng for Coins {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("unexpected HPKE randomness request")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("unexpected HPKE randomness request")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(!self.used && dst.len() == 32);
        dst.copy_from_slice(&*self.bytes);
        self.used = true;
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Coins {}
/// Deterministic public fixture interface ONLY. Normal callers use device_seal.
pub fn fixture_device_seal(
    c: &Context,
    device: &[u8; 16],
    pk: &[u8; 32],
    amk: &[u8; 32],
    ikm: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let info = device_data(c, device, pk, None)?;
    let pkx = <X as Kem>::PublicKey::from_bytes(pk).map_err(|_| Error::InvalidContext)?;
    let mut rng = Coins {
        bytes: Zeroizing::new(*ikm),
        used: false,
    };
    let (enc, mut ctx) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X>(
        &OpModeS::Base,
        &pkx,
        &info,
        &mut rng,
    )
    .map_err(|_| Error::Authentication)?;
    let mut h = b"PTK1".to_vec();
    h.extend(enc.to_bytes());
    let aad = device_data(c, device, pk, Some(&h))?;
    h.extend(
        ctx.seal(&plaintext(amk), &aad)
            .map_err(|_| Error::Authentication)?,
    );
    Ok(h)
}
pub fn device_open(
    c: &Context,
    device: &[u8; 16],
    sk: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if envelope.len() != 308 || &envelope[..4] != b"PTK1" {
        return Err(Error::InvalidEnvelope);
    }
    let sk = <X as Kem>::PrivateKey::from_bytes(sk).map_err(|_| Error::InvalidContext)?;
    let pk: [u8; 32] = X::sk_to_pk(&sk).to_bytes().as_slice().try_into().unwrap();
    let info = device_data(c, device, &pk, None)?;
    let aad = device_data(c, device, &pk, Some(&envelope[..36]))?;
    let enc = <X as Kem>::EncappedKey::from_bytes(&envelope[4..36])
        .map_err(|_| Error::InvalidEnvelope)?;
    let mut ctx =
        hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X>(&OpModeR::Base, &sk, &enc, &info)
            .map_err(|_| Error::Authentication)?;
    let p = Zeroizing::new(
        ctx.open(&envelope[36..], &aad)
            .map_err(|_| Error::Authentication)?,
    );
    parse(&p)
}
/// Deterministic fixture interface, NOT an entropy-generating wrapper.
pub fn fixture_recovery_seal(
    c: &Context,
    secret: &[u8; 32],
    amk: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, Error> {
    let k = hkdf_key(secret, None, &domain("recovery/key", c)?);
    let mut h = b"PTR1".to_vec();
    h.extend(nonce);
    let mut aad = domain("recovery/aad", c)?;
    aad.extend(&h);
    h.extend(encrypt(&k, nonce, &aad, amk)?);
    Ok(h)
}
pub fn recovery_open(
    c: &Context,
    secret: &[u8; 32],
    e: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if e.len() != 300 || &e[..4] != b"PTR1" {
        return Err(Error::InvalidEnvelope);
    }
    let k = hkdf_key(secret, None, &domain("recovery/key", c)?);
    let mut aad = domain("recovery/aad", c)?;
    aad.extend(&e[..28]);
    decrypt(&k, e[4..28].try_into().unwrap(), &aad, &e[28..])
}
fn password_valid(password: &[u8], t: u32) -> Result<(), Error> {
    if password.is_empty()
        || password.len() > 1024
        || core::str::from_utf8(password).is_err()
        || ![3, 4].contains(&t)
    {
        return Err(Error::InvalidContext);
    }
    Ok(())
}
pub fn password_key(
    c: &Context,
    password: &[u8],
    salt: &[u8; 16],
    t: u32,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    password_valid(password, t)?;
    let info = domain("password/key", c)?;
    let mut raw = Zeroizing::new([0; 32]);
    // Library's allocating convenience method frees but does not wipe the arena.
    // Own the fixed allowlisted arena so all 64 MiB are wiped on every return.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(65536)
        .map_err(|_| Error::TooLarge)?;
    memory.resize(65536, argon2::Block::default());
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, t, 1, Some(32)).map_err(|_| Error::InvalidContext)?,
    )
    .hash_password_into_with_memory(password, salt, raw.as_mut(), &mut memory)
    .map_err(|_| Error::InvalidContext)?;
    Ok(hkdf_key(&*raw, None, &info))
}
/// t=3 default, t=4 explicit upgrade. Deterministic fixture/browser entropy boundary only.
pub fn fixture_password_seal(
    c: &Context,
    password: &[u8],
    amk: &[u8; 32],
    salt: &[u8; 16],
    nonce: &[u8; 24],
    t: u32,
) -> Result<Vec<u8>, Error> {
    let k = password_key(c, password, salt, t)?;
    let mut h = b"PTW1".to_vec();
    h.extend(salt);
    h.extend(65536u32.to_le_bytes());
    h.extend(t.to_le_bytes());
    h.extend(1u32.to_le_bytes());
    h.extend(nonce);
    let mut aad = domain("password/aad", c)?;
    aad.extend(&h);
    h.extend(encrypt(&k, nonce, &aad, amk)?);
    Ok(h)
}
pub fn password_open(c: &Context, password: &[u8], e: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if e.len() != 328 || &e[..4] != b"PTW1" {
        return Err(Error::InvalidEnvelope);
    }
    // Reject all unapproved memory/lane/time tuples BEFORE invoking Argon2.
    let m = u32::from_le_bytes(e[20..24].try_into().unwrap());
    let t = u32::from_le_bytes(e[24..28].try_into().unwrap());
    let p = u32::from_le_bytes(e[28..32].try_into().unwrap());
    if m != 65536 || p != 1 || ![3, 4].contains(&t) {
        return Err(Error::InvalidContext);
    }
    let k = password_key(c, password, e[4..20].try_into().unwrap(), t)?;
    let mut aad = domain("password/aad", c)?;
    aad.extend(&e[..56]);
    decrypt(&k, e[32..56].try_into().unwrap(), &aad, &e[56..])
}
#[cfg(any(target_os = "linux", test))]
fn fresh<const N: usize>(
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Zeroizing<[u8; N]>, Error> {
    let mut b = Zeroizing::new([0; N]);
    fill(b.as_mut())?;
    Ok(b)
}
#[cfg(target_os = "linux")]
fn os_fill(b: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(b).map_err(|_| Error::EntropyUnavailable)
}
#[cfg(target_os = "linux")]
pub fn device_seal(
    c: &Context,
    device: &[u8; 16],
    pk: &[u8; 32],
    amk: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    c.bytes()?;
    let coins = fresh::<32>(&mut os_fill)?;
    fixture_device_seal(c, device, pk, amk, &coins)
}
#[cfg(target_os = "linux")]
pub fn recovery_seal(c: &Context, secret: &[u8; 32], amk: &[u8; 32]) -> Result<Vec<u8>, Error> {
    recovery_with_entropy(c, secret, amk, &mut os_fill)
}
#[cfg(any(target_os = "linux", test))]
fn recovery_with_entropy(
    c: &Context,
    secret: &[u8; 32],
    amk: &[u8; 32],
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    c.bytes()?;
    let nonce = fresh::<24>(fill)?;
    fixture_recovery_seal(c, secret, amk, &nonce)
}
#[cfg(target_os = "linux")]
pub fn password_seal(
    c: &Context,
    password: &[u8],
    amk: &[u8; 32],
    upgrade: bool,
) -> Result<Vec<u8>, Error> {
    password_with_entropy(c, password, amk, upgrade, &mut os_fill)
}
#[cfg(any(target_os = "linux", test))]
fn password_with_entropy(
    c: &Context,
    password: &[u8],
    amk: &[u8; 32],
    upgrade: bool,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let t = if upgrade { 4 } else { 3 };
    c.bytes()?;
    password_valid(password, t)?;
    let salt = fresh::<16>(fill)?;
    let nonce = fresh::<24>(fill)?;
    fixture_password_seal(c, password, amk, &salt, &nonce, t)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_failure_and_partial_write() {
        let c = Context {
            owner_id: [1; 16],
            envelope_id: [2; 16],
            amk_version: 1,
            format_version: 1,
        };
        for partial in [false, true] {
            let mut fail = |b: &mut [u8]| {
                if partial {
                    b[0] = 9;
                }
                Err(Error::EntropyUnavailable)
            };
            assert!(recovery_with_entropy(&c, &[1; 32], &[2; 32], &mut fail).is_err());
            assert!(password_with_entropy(&c, b"pass", &[2; 32], false, &mut fail).is_err());
            assert!(fresh::<32>(&mut fail).is_err());
        }
        let mut calls = 0;
        let mut fail_second = |b: &mut [u8]| {
            calls += 1;
            b.fill(7);
            if calls == 2 {
                Err(Error::EntropyUnavailable)
            } else {
                Ok(())
            }
        };
        assert!(password_with_entropy(&c, b"pass", &[2; 32], false, &mut fail_second).is_err());
        assert_eq!(calls, 2);
    }
}
