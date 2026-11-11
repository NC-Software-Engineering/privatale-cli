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
use hpke::{Deserializable, Kem, Serializable, kem::X25519HkdfSha256 as X};
use privatale_core::amk_v1::{self as a, Context};
fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn context(b: &[u8]) -> Context {
    Context {
        owner_id: b[..16].try_into().unwrap(),
        envelope_id: b[16..32].try_into().unwrap(),
        amk_version: u32::from_le_bytes(b[32..36].try_into().unwrap()),
        format_version: u32::from_le_bytes(b[36..40].try_into().unwrap()),
    }
}
#[cfg_attr(test, test)]
pub fn amk_full_vectors() {
    let mut count = 0;
    for line in include_str!("../../../test-vectors/amk-v1.csv")
        .lines()
        .skip(1)
    {
        let f: Vec<_> = line.split(',').collect();
        assert_eq!(f.len(), 12);
        let t = f[1].parse().unwrap();
        let secret = hex(f[2]);
        let coins = hex(f[3]);
        let c = context(&hex(f[4]));
        let extra = hex(f[5]);
        let amk = hex(f[6]).try_into().unwrap();
        assert_eq!(&*a::plaintext(&amk), &hex(f[10]));
        let expected = hex(f[11]);
        let (sealed, opened) = match f[0] {
            "device" => {
                let device = extra[..16].try_into().unwrap();
                let pk = extra[16..].try_into().unwrap();
                (
                    a::fixture_device_seal(
                        &c,
                        device,
                        pk,
                        &amk,
                        coins.as_slice().try_into().unwrap(),
                    )
                    .unwrap(),
                    a::device_open(&c, device, secret.as_slice().try_into().unwrap(), &expected)
                        .unwrap(),
                )
            }
            "recovery" => {
                assert_eq!(&*a::hkdf_key(&secret, None, &hex(f[7])), &hex(f[8])[..]);
                (
                    a::fixture_recovery_seal(
                        &c,
                        secret.as_slice().try_into().unwrap(),
                        &amk,
                        coins.as_slice().try_into().unwrap(),
                    )
                    .unwrap(),
                    a::recovery_open(&c, secret.as_slice().try_into().unwrap(), &expected).unwrap(),
                )
            }
            "password" => {
                assert_eq!(
                    &*a::password_key(&c, &secret, coins[..16].try_into().unwrap(), t).unwrap(),
                    &hex(f[8])[..]
                );
                (
                    a::fixture_password_seal(
                        &c,
                        &secret,
                        &amk,
                        coins[..16].try_into().unwrap(),
                        coins[16..].try_into().unwrap(),
                        t,
                    )
                    .unwrap(),
                    a::password_open(&c, &secret, &expected).unwrap(),
                )
            }
            _ => panic!(),
        };
        assert_eq!(sealed, expected);
        assert_eq!(*opened, amk);
        count += 1;
    }
    assert_eq!(count, 4);
}
struct Coins(Vec<u8>);
impl rand_core::TryRng for Coins {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!()
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(b.len(), self.0.len());
        b.copy_from_slice(&self.0);
        self.0.clear();
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Coins {}
#[cfg_attr(test, test)]
pub fn official_hpke_and_argon() {
    let f: Vec<_> = include_str!("../../../test-vectors/hpke-official.csv")
        .lines()
        .nth(1)
        .unwrap()
        .split(',')
        .map(hex)
        .collect();
    let pk = <X as Kem>::PublicKey::from_bytes(&f[1]).unwrap();
    let sk = <X as Kem>::PrivateKey::from_bytes(&f[2]).unwrap();
    assert_eq!(X::sk_to_pk(&sk).to_bytes().as_slice(), f[1]);
    let (enc, mut s) = hpke::setup_sender_with_rng::<
        hpke::aead::ChaCha20Poly1305,
        hpke::kdf::HkdfSha256,
        X,
    >(&hpke::OpModeS::Base, &pk, &f[3], &mut Coins(f[0].clone()))
    .unwrap();
    assert_eq!(enc.to_bytes().as_slice(), f[6]);
    assert_eq!(s.seal(&f[5], &f[4]).unwrap(), f[7]);
    let mut r = hpke::setup_receiver::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, X>(
        &hpke::OpModeR::Base,
        &sk,
        &enc,
        &f[3],
    )
    .unwrap();
    assert_eq!(r.open(&f[7], &f[4]).unwrap(), f[5]);
    // RFC 9106 section 5.3, deliberately separate from the no-secret/AD wrapper.
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(argon2::AssociatedData::new(&[4; 12]).unwrap());
    let params = builder.build().unwrap();
    let mut out = [0; 32];
    argon2::Argon2::new_with_secret(
        &[3; 8],
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .unwrap()
    .hash_password_into(&[1; 32], &[2; 16], &mut out)
    .unwrap();
    assert_eq!(
        out.as_slice(),
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}
#[cfg_attr(test, test)]
pub fn amk_refusals_and_rewrap() {
    let c = Context {
        owner_id: [1; 16],
        envelope_id: [2; 16],
        amk_version: 1,
        format_version: 1,
    };
    let secret = [3; 32];
    let amk = [4; 32];
    let e = a::fixture_recovery_seal(&c, &secret, &amk, &[5; 24]).unwrap();
    for i in 0..e.len() {
        let mut bad = e.clone();
        bad[i] ^= 1;
        assert!(a::recovery_open(&c, &secret, &bad).is_err());
    }
    for n in 0..e.len() {
        assert!(a::recovery_open(&c, &secret, &e[..n]).is_err());
    }
    for i in 0..4 {
        let mut bad = c.clone();
        match i {
            0 => bad.owner_id[0] ^= 1,
            1 => bad.envelope_id[0] ^= 1,
            2 => bad.amk_version = 2,
            _ => bad.format_version = 2,
        };
        assert!(a::recovery_open(&bad, &secret, &e).is_err());
    }
    let mut invalid = c.clone();
    invalid.amk_version = 0;
    assert!(a::fixture_recovery_seal(&invalid, &secret, &amk, &[5; 24]).is_err());
    assert!(a::recovery_open(&c, &[9; 32], &e).is_err());
    let sk = <X as Kem>::PrivateKey::from_bytes(&secret).unwrap();
    let pk: [u8; 32] = X::sk_to_pk(&sk).to_bytes().as_slice().try_into().unwrap();
    let dev = [8; 16];
    let d = a::fixture_device_seal(&c, &dev, &pk, &amk, &[6; 32]).unwrap();
    assert!(a::fixture_device_seal(&c, &dev, &[0; 32], &amk, &[6; 32]).is_err());
    assert!(a::fixture_device_seal(&c, &dev, &[1; 32], &amk, &[6; 32]).is_ok());
    for i in [0, 4, 35, 36, 307] {
        let mut bad = d.clone();
        bad[i] ^= 1;
        assert!(a::device_open(&c, &dev, &secret, &bad).is_err());
    }
    assert!(a::device_open(&c, &[9; 16], &secret, &d).is_err());
    assert!(a::device_open(&c, &dev, &[9; 32], &d).is_err());
    let mut weak_pk = [0; 32];
    weak_pk[0] = 1;
    assert!(a::fixture_device_seal(&c, &dev, &weak_pk, &amk, &[6; 32]).is_err());
    let mut weak = d.clone();
    weak[4..36].fill(0);
    assert!(a::device_open(&c, &dev, &secret, &weak).is_err());
    let p = a::fixture_password_seal(&c, b"old pass", &amk, &[7; 16], &[8; 24], 3).unwrap();
    for (offset, v) in [
        (20, 65535u32),
        (20, 65537),
        (24, 2),
        (24, 5),
        (28, 0),
        (28, 2),
    ] {
        let mut bad = p.clone();
        bad[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
        assert!(a::password_open(&c, b"old pass", &bad).is_err());
    }
    for password in [vec![], vec![b'a'; 1025], vec![255]] {
        assert!(a::password_open(&c, &password, &p).is_err());
        assert!(a::fixture_password_seal(&c, &password, &amk, &[7; 16], &[8; 24], 3).is_err());
    }
    assert!(a::password_open(&c, b"wrong pass", &p).is_err());
    for offset in [4, 32, 327] {
        let mut bad = p.clone();
        bad[offset] ^= 1;
        assert!(a::password_open(&c, b"old pass", &bad).is_err());
    }
    let mut wrong = c.clone();
    wrong.owner_id[0] ^= 1;
    assert!(a::password_open(&wrong, b"old pass", &p).is_err());
    assert!(a::device_open(&wrong, &dev, &secret, &d).is_err());

    let mut new = c.clone();
    new.envelope_id = [10; 16];
    let rewrapped =
        a::fixture_password_seal(&new, b"new pass", &amk, &[11; 16], &[12; 24], 4).unwrap();
    assert_eq!(
        *a::password_open(&new, b"new pass", &rewrapped).unwrap(),
        amk
    );
    assert_eq!(*a::recovery_open(&c, &secret, &e).unwrap(), amk);
    assert_eq!(*a::device_open(&c, &dev, &secret, &d).unwrap(), amk);
    assert_eq!(&rewrapped[24..28], &4u32.to_le_bytes());
}

#[cfg_attr(test, test)]
pub fn amk_authenticated_frame_refusals() {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    let f: Vec<_> = include_str!("../../../test-vectors/amk-v1.csv")
        .lines()
        .nth(2)
        .unwrap()
        .split(',')
        .collect();
    let c = context(&hex(f[4]));
    let secret: [u8; 32] = hex(f[2]).try_into().unwrap();
    let key: [u8; 32] = hex(f[8]).try_into().unwrap();
    let aad = hex(f[9]);
    let envelope = hex(f[11]);
    let nonce: &[u8; 24] = envelope[4..28].try_into().unwrap();
    for offset in [0, 3, 36, 255] {
        let mut p = hex(f[10]);
        p[offset] ^= 1;
        let ct = XChaCha20Poly1305::new((&key).into())
            .encrypt(nonce.into(), Payload { msg: &p, aad: &aad })
            .unwrap();
        let mut bad = envelope[..28].to_vec();
        bad.extend(ct);
        assert!(a::recovery_open(&c, &secret, &bad).is_err());
    }
}
