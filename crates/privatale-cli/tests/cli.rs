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
use std::process::Command;

#[test]
fn cli_calls_core_and_rejects_invalid_inputs() {
    let binary = env!("CARGO_BIN_EXE_privatale-prototype");
    let result = Command::new(binary)
        .args(["padme-length", "257"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"272\n");
    assert!(result.stderr.is_empty());
    for input in ["-1", "text", "18446744073709551615", "18446744073709551616"] {
        let result = Command::new(binary)
            .args(["padme-length", input])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(input));
    }
    assert_eq!(
        Command::new(binary).output().unwrap().status.code(),
        Some(2)
    );
}
