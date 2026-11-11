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
//! Linux-only P1 експеримент със системен CSPRNG, без storage/реални данни.
//! Случайните 192-bit nonce имат пренебрежима, но не нулева вероятност за колизия.
//! Няма persistent nonce registry или browser entropy adapter.
use crate::{envelope, framing};

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    EntropyUnavailable,
    Envelope(envelope::Error),
}

/// Генерира нов nonce за всяко извикване; няма fallback при системна грешка.
/// Това не генерира ключ и не прави временния PTE0 продуктов формат.
pub fn seal(
    key: &[u8; 32],
    context: &envelope::Context,
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    seal_from_entropy(key, context, payload, |nonce| {
        getrandom::fill(nonce).map_err(|_| ())
    })
}

// Private seam: външен caller не може да подаде предвидим RNG на seal().
fn seal_from_entropy(
    key: &[u8; 32],
    context: &envelope::Context,
    payload: &[u8],
    fill: impl FnOnce(&mut [u8; 24]) -> Result<(), ()>,
) -> Result<Vec<u8>, SealError> {
    envelope::aad(context).map_err(SealError::Envelope)?;
    if payload.len() > framing::MAX_PAYLOAD_LEN {
        return Err(SealError::Envelope(envelope::Error::Frame(
            framing::FrameError::TooLarge,
        )));
    }
    let mut nonce = [0; 24];
    fill(&mut nonce).map_err(|_| SealError::EntropyUnavailable)?;
    envelope::seal_with_nonce(key, &nonce, context, payload).map_err(SealError::Envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> envelope::Context {
        envelope::Context {
            owner_id: b"synthetic-linux".to_vec(),
            doc_id: [1; 16],
            item_id: [2; 16],
            key_version: 1,
            format_version: 0,
        }
    }

    #[test]
    fn entropy_error_and_partial_write_fail_closed() {
        for partial in [false, true] {
            let result = seal_from_entropy(&[3; 32], &context(), b"synthetic", |nonce| {
                if partial {
                    nonce[..12].fill(42);
                }
                Err(())
            });
            assert_eq!(result, Err(SealError::EntropyUnavailable));
        }
    }

    #[test]
    fn uses_exactly_the_supplied_24_bytes_once() {
        let ctx = context();
        let key = [3; 32];
        let nonce = std::array::from_fn(|i| i as u8);
        let mut calls = 0;
        let result = seal_from_entropy(&key, &ctx, b"synthetic", |out| {
            calls += 1;
            *out = nonce;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(&result[4..28], &nonce);
        assert_eq!(
            result,
            envelope::seal_with_nonce(&key, &nonce, &ctx, b"synthetic").unwrap()
        );
        assert_eq!(envelope::open(&key, &ctx, &result).unwrap(), b"synthetic");
    }

    #[test]
    fn invalid_inputs_do_not_consume_entropy() {
        let mut ctx = context();
        ctx.format_version = 1;
        assert_eq!(
            seal_from_entropy(&[3; 32], &ctx, b"", |_| panic!("unexpected RNG call")),
            Err(SealError::Envelope(envelope::Error::InvalidContext))
        );
        assert_eq!(
            seal_from_entropy(
                &[3; 32],
                &context(),
                &vec![0; framing::MAX_PAYLOAD_LEN + 1],
                |_| panic!("unexpected RNG call")
            ),
            Err(SealError::Envelope(envelope::Error::Frame(
                framing::FrameError::TooLarge
            )))
        );
    }

    #[test]
    fn real_linux_entropy_smoke() {
        let ctx = context();
        let key = crate::keys::derive_document_key(&[4; 32], &ctx.doc_id, ctx.key_version);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let result = seal(&key, &ctx, b"synthetic").unwrap();
            assert_eq!(result.len(), 300);
            assert!(
                seen.insert(result[4..28].to_vec()),
                "duplicate nonce in smoke sample"
            );
            assert_eq!(envelope::open(&key, &ctx, &result).unwrap(), b"synthetic");
        }
        // Smoke sample only: not an entropy-quality test or uniqueness proof.
    }
}
