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
use privatale_core::framing::{FrameError, MAX_PAYLOAD_LEN, decode, encode};

#[cfg_attr(test, test)]
pub fn exact_bytes_and_binary_roundtrip() {
    let payload = [0, 255, 0x80, 42, 0];
    let mut expected = vec![0; 256];
    expected[..12].copy_from_slice(&[80, 84, 80, 48, 5, 0, 0, 0, 0, 0, 0, 0]);
    expected[12..17].copy_from_slice(&payload);
    let frame = encode(&payload).unwrap();
    assert_eq!(frame, expected);
    let decoded = decode(&frame).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.as_ptr(), frame[12..].as_ptr());
}

#[cfg_attr(test, test)]
pub fn independent_length_vectors_include_header() {
    // payload bytes, Padmé(header + payload); очакванията не викат helper-а.
    for (length, expected) in [
        (0, 256),
        (1, 256),
        (243, 256),
        (244, 256),
        (245, 272),
        (260, 272),
        (261, 288),
        (499, 512),
        (500, 512),
        (501, 544),
        (1012, 1024),
        (1013, 1088),
        (MAX_PAYLOAD_LEN, 1081344),
    ] {
        let payload = vec![0xa5; length];
        let frame = encode(&payload).unwrap();
        assert_eq!(frame.len(), expected, "payload length {length}");
        // Независим byte oracle за целия frame, не само roundtrip/дължина.
        let mut expected_frame = b"PTP0".to_vec();
        expected_frame.extend_from_slice(&(length as u64).to_le_bytes());
        expected_frame.extend_from_slice(&payload);
        expected_frame.resize(expected, 0);
        assert_eq!(frame, expected_frame, "frame bytes for length {length}");
        assert_eq!(decode(&frame).unwrap(), payload);
        assert_eq!(encode(decode(&frame).unwrap()).unwrap(), frame);
    }
}

#[cfg_attr(test, test)]
pub fn all_truncations_and_extra_bytes_are_rejected() {
    let frame = encode(&vec![42; 501]).unwrap();
    for length in 0..frame.len() {
        assert!(decode(&frame[..length]).is_err(), "truncation {length}");
    }
    let mut extra = frame.clone();
    extra.push(0);
    assert_eq!(decode(&extra), Err(FrameError::InvalidLength));
    // Дори подравнен, но не минимален размер е неканоничен.
    extra.resize(1024, 0);
    assert_eq!(decode(&extra), Err(FrameError::InvalidLength));
}

#[cfg_attr(test, test)]
pub fn unknown_header_and_each_nonzero_padding_byte_are_rejected() {
    let frame = encode(b"synthetic").unwrap();
    for offset in 0..4 {
        let mut changed = frame.clone();
        changed[offset] ^= 1;
        assert_eq!(decode(&changed), Err(FrameError::InvalidHeader));
    }
    for offset in 21..frame.len() {
        let mut changed = frame.clone();
        changed[offset] = 1;
        assert_eq!(decode(&changed), Err(FrameError::InvalidPadding));
    }
}

#[cfg_attr(test, test)]
pub fn forged_lengths_and_resource_limits_are_rejected() {
    let mut frame = encode(b"synthetic").unwrap();
    for length in [MAX_PAYLOAD_LEN as u64 + 1, u32::MAX as u64, u64::MAX] {
        frame[4..12].copy_from_slice(&length.to_le_bytes());
        assert_eq!(decode(&frame), Err(FrameError::TooLarge));
    }
    frame[4..12].copy_from_slice(&501_u64.to_le_bytes());
    assert_eq!(decode(&frame), Err(FrameError::InvalidLength));
    assert_eq!(
        encode(&vec![0; MAX_PAYLOAD_LEN + 1]),
        Err(FrameError::TooLarge)
    );
    assert_eq!(decode(&vec![0; 1081345]), Err(FrameError::TooLarge));
}

#[cfg_attr(test, test)]
pub fn framing_is_not_authentication() {
    let mut frame = encode(b"synthetic").unwrap();
    frame[12] ^= 1;
    // Нарочно показва границата: нужен е AEAD, не само този parser.
    assert!(decode(&frame).is_ok());
    assert_ne!(decode(&frame).unwrap(), b"synthetic");
}
