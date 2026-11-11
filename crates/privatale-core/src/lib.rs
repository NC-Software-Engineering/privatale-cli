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
//! Изолиран P1 прототип: Padmé, временен framing и синтетичен AEAD плик.
//! Не определя продуктов formatVersion 1 или готов клиентски crypto API.

pub mod amk_v1;
pub mod blob_v1;
pub mod envelope;
pub mod framing;
pub mod keys;
#[cfg(target_os = "linux")]
pub mod linux_crypto;
pub mod sync_item_v1;

/// Padmé: E = floor(log2(L)), S = floor(log2(E)) + 1;
/// закръгляне нагоре до кратно на 2^(E-S), минимум 256 байта.
/// Само целочислена аритметика; None означава препълване на u64.
pub fn padded_len(length: u64) -> Option<u64> {
    let length = length.max(256);
    let exponent = 63 - length.leading_zeros();
    let significant_bits = 32 - exponent.leading_zeros();
    let mask = (1_u64 << (exponent - significant_bits)) - 1;
    length.checked_add(mask).map(|value| value & !mask)
}

/// Само прототипен WASM ABI. Нула обозначава препълване, никога валидна дължина.
#[unsafe(no_mangle)]
pub extern "C" fn prototype_padme_len(length: u64) -> u64 {
    padded_len(length).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_vectors() {
        for line in include_str!("../../../test-vectors/padme.csv")
            .lines()
            .skip(1)
        {
            let (input, expected) = line.split_once(',').unwrap();
            let input = input.parse().unwrap();
            let expected = if expected == "overflow" {
                None
            } else {
                Some(expected.parse().unwrap())
            };
            assert_eq!(padded_len(input), expected, "дължина {input}");
        }
    }

    #[test]
    fn monotonic_idempotent_and_never_shorter() {
        let mut previous = 256;
        for input in 0..100_000 {
            let padded = padded_len(input).unwrap();
            assert!(padded >= input && padded >= 256 && padded >= previous);
            assert_eq!(padded_len(padded), Some(padded));
            previous = padded;
        }
    }

    #[test]
    fn power_boundaries_and_overflow() {
        for bit in 8..64 {
            let power = 1_u64 << bit;
            assert_eq!(padded_len(power), Some(power));
            assert_eq!(padded_len(power - 1), Some(power));
            assert!(padded_len(power + 1).unwrap() > power);
        }
        // Най-голямото представимо подравнено число; следващото препълва.
        let largest = !((1_u64 << 57) - 1);
        assert_eq!(padded_len(largest), Some(largest));
        assert_eq!(padded_len(largest + 1), None);
        assert_eq!(prototype_padme_len(u64::MAX), 0);
    }
}
