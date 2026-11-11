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
//! Temporary byte-at-a-time bridge, not a product ABI. No raw pointers/unsafe blocks.
//! Request: key32 | nonce24 | doc16 | item16 | keyVersion LE4 | format LE4 |
//! ownerLength LE4 | owner | payload/envelope. open ignores the request nonce.
use privatale_core::envelope::{self, Context};
use std::cell::RefCell;
use zeroize::Zeroizing;

const LIMIT: usize = 2 * 1024 * 1024;
#[derive(Default)]
struct State {
    input: Zeroizing<Vec<u8>>,
    output: Zeroizing<Vec<u8>>,
    closed: bool,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

#[unsafe(no_mangle)]
pub extern "C" fn bridge_reset() {
    STATE.with(|state| *state.borrow_mut() = State::default());
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_push(byte: u32) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.closed || byte > 255 || state.input.len() >= LIMIT {
            *state = State {
                closed: true,
                ..State::default()
            };
            return 1;
        }
        // Reserve once, before receiving any key bytes: no reallocating secret copies.
        if state.input.capacity() == 0 {
            state.input.reserve_exact(LIMIT);
        }
        state.input.push(byte as u8);
        0
    })
}

fn execute(operation: u32, request: &[u8]) -> Result<Vec<u8>, ()> {
    if request.len() < 100 {
        return Err(());
    }
    let owner_len = u32::from_le_bytes(request[96..100].try_into().map_err(|_| ())?) as usize;
    if !(1..=1024).contains(&owner_len) || request.len() < 100 + owner_len {
        return Err(());
    }
    let context = Context {
        owner_id: request[100..100 + owner_len].to_vec(),
        doc_id: request[56..72].try_into().map_err(|_| ())?,
        item_id: request[72..88].try_into().map_err(|_| ())?,
        key_version: u32::from_le_bytes(request[88..92].try_into().map_err(|_| ())?),
        format_version: u32::from_le_bytes(request[92..96].try_into().map_err(|_| ())?),
    };
    let key: &[u8; 32] = request[..32].try_into().map_err(|_| ())?;
    let data = &request[100 + owner_len..];
    match operation {
        1 => envelope::seal_with_nonce(
            key,
            request[32..56].try_into().map_err(|_| ())?,
            &context,
            data,
        ),
        2 => envelope::open(key, &context, data),
        _ => return Err(()),
    }
    .map_err(|_| ())
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_run(operation: u32) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.output = Zeroizing::new(Vec::new());
        if state.closed {
            return 1;
        }
        state.closed = true;
        let input = std::mem::take(&mut state.input);
        match execute(operation, &input) {
            Ok(output) => {
                state.output = Zeroizing::new(output);
                0
            }
            Err(()) => 1,
        }
        // input (including key/plaintext) is zeroized on drop, also on errors.
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_len() -> u32 {
    STATE.with(|state| state.borrow().output.len() as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn bridge_byte(index: u32) -> u32 {
    STATE.with(|state| {
        state
            .borrow()
            .output
            .get(index as usize)
            .map_or(256, |b| u32::from(*b))
    })
}
