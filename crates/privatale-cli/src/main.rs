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
use privatale_core::padded_len;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("privatale-prototype {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [command, input] if command == "padme-length" => {
            match input.parse::<u64>().ok().and_then(padded_len) {
                Some(length) => {
                    println!("{length}");
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("Невалидна дължина или препълване.");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            eprintln!("Прототип: privatale-prototype --version | padme-length <брой-байтове>");
            ExitCode::from(2)
        }
    }
}
