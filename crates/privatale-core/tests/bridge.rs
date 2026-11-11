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
#[path = "../examples/browser-bridge.rs"]
mod bridge;
use bridge::*;

fn request() -> Vec<u8> {
    let mut bytes = vec![0; 100];
    bytes[96] = 1;
    bytes.push(b'x');
    bytes.extend_from_slice(b"synthetic");
    bytes
}
fn submit(bytes: &[u8], operation: u32) -> u32 {
    bridge_reset();
    for byte in bytes {
        assert_eq!(bridge_push(u32::from(*byte)), 0);
    }
    bridge_run(operation)
}
fn output() -> Vec<u8> {
    (0..bridge_len()).map(|i| bridge_byte(i) as u8).collect()
}

#[test]
fn roundtrip_and_no_stale_plaintext() {
    let input = request();
    assert_eq!(submit(&input, 1), 0);
    let sealed = output();
    assert_eq!(sealed.len(), 300);
    let mut open = input[..101].to_vec();
    open.extend_from_slice(&sealed);
    assert_eq!(submit(&open, 2), 0);
    assert_eq!(output(), b"synthetic");
    assert_eq!(bridge_run(2), 1); // request is one-shot, output is discarded.
    assert_eq!(bridge_len(), 0);
    assert_eq!(bridge_byte(0), 256);
    *open.last_mut().unwrap() ^= 1;
    assert_eq!(submit(&open, 2), 1);
    assert_eq!(bridge_len(), 0);
    bridge_reset();
}

#[test]
fn malformed_bounds_and_reset() {
    let valid = request();
    for length in 0..101 {
        assert_eq!(submit(&valid[..length], 1), 1);
    }
    let mut bad = valid.clone();
    bad[96..100].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(submit(&bad, 1), 1);
    assert_eq!(submit(&valid, 99), 1);
    assert_eq!(bridge_byte(u32::MAX), 256);
    bridge_reset();
    assert_eq!(bridge_push(256), 1);
    assert_eq!(bridge_push(1), 1);
    assert_eq!(bridge_run(1), 1);
    bridge_reset();
    for _ in 0..2 * 1024 * 1024 {
        assert_eq!(bridge_push(0), 0);
    }
    assert_eq!(bridge_push(0), 1);
    assert_eq!(bridge_len(), 0);
    assert_eq!(submit(&valid, 1), 0); // explicit reset recovers.
    bridge_reset();
}
