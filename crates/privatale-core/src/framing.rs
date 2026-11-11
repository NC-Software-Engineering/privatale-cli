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
//! Временен P1 формат за синтетични данни, НЕ продуктов formatVersion 1.
//! `PTP0` | u64 little-endian дължина | payload | нулев Padmé padding.
//! Няма удостоверяване: бъдещият AEAD слой трябва да проверява tag ПРЕДИ decode.

use crate::padded_len;

const MAGIC: &[u8; 4] = b"PTP0";
const HEADER_LEN: usize = 12;
/// Само ресурсен лимит на прототипа; не продуктова квота или лимит за медия.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    InvalidHeader,
    InvalidLength,
    InvalidPadding,
}

/// Сериализира байтове; включва header-а в подравняваната дължина.
/// Не криптира и не е подходящо за записване на реални дневници.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::TooLarge);
    }
    // Лимитът по-горе гарантира представимост на двете поддържани цели.
    let end = HEADER_LEN + payload.len();
    let size = padded_len(end as u64).ok_or(FrameError::TooLarge)? as usize;
    let mut frame = vec![0; size];
    frame[..4].copy_from_slice(MAGIC);
    frame[4..HEADER_LEN].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    frame[HEADER_LEN..end].copy_from_slice(payload);
    Ok(frame)
}

/// Строго декодиране без алокация; връща зает slice само след всички проверки.
/// Структурната валидност НЕ доказва целостта или автентичността на payload-а.
pub fn decode(frame: &[u8]) -> Result<&[u8], FrameError> {
    let max_frame = padded_len((HEADER_LEN + MAX_PAYLOAD_LEN) as u64).unwrap() as usize;
    if frame.len() > max_frame {
        return Err(FrameError::TooLarge);
    }
    if frame.len() < HEADER_LEN || &frame[..4] != MAGIC {
        return Err(FrameError::InvalidHeader);
    }
    let length = u64::from_le_bytes(frame[4..HEADER_LEN].try_into().unwrap());
    // Проверка преди преобразуване към usize, включително за 32-bit WASM.
    if length > MAX_PAYLOAD_LEN as u64 {
        return Err(FrameError::TooLarge);
    }
    let end = HEADER_LEN + length as usize;
    let expected = padded_len(end as u64).ok_or(FrameError::TooLarge)? as usize;
    if frame.len() != expected {
        return Err(FrameError::InvalidLength);
    }
    if frame[end..].iter().any(|byte| *byte != 0) {
        return Err(FrameError::InvalidPadding);
    }
    Ok(&frame[HEADER_LEN..end])
}
