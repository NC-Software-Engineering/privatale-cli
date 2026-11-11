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
//! Synthetic native measurement only; same fixed allowlisted KDF as WASM.
use privatale_core::amk_v1::{Context, password_key};
fn main() {
    let c = Context {
        owner_id: [1; 16],
        envelope_id: [2; 16],
        amk_version: 1,
        format_version: 1,
    };
    for t in [3, 4] {
        let start = std::time::Instant::now();
        let k = password_key(&c, b"P1 synthetic password", &[3; 16], t).unwrap();
        assert_ne!(*k, [0; 32]);
        let rss = std::fs::read_to_string("/proc/self/status").unwrap();
        let peak = rss.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
        println!(
            "Argon2id m=65536KiB t={t} p=1 arena=67108864 bytes time_ms={} {peak}",
            start.elapsed().as_millis()
        );
    }
}
