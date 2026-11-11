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
//! Самостоятелен harness: същите assertions като native интеграционния тест.
//! Panic във WASM става trap и Node runner-ът отчита провал, не PASS.

#[path = "../tests/framing.rs"]
mod cases;
#[path = "../tests/envelope.rs"]
mod crypto_cases;
#[path = "../tests/keys.rs"]
mod key_cases;
#[path = "../tests/sync_item_v1.rs"]
mod v1_cases;
use crypto_cases::{
    authenticated_invalid_frame_is_rejected, envelope_rejects_mutations_and_wrong_context,
    envelope_roundtrip_and_context_bytes, independent_pte0_golden_vectors,
    published_xchacha_vector,
};

macro_rules! export_case {
    ($name:ident) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $name() {
            cases::$name();
        }
    };
}

export_case!(exact_bytes_and_binary_roundtrip);
export_case!(independent_length_vectors_include_header);
export_case!(all_truncations_and_extra_bytes_are_rejected);
export_case!(unknown_header_and_each_nonzero_padding_byte_are_rejected);
export_case!(forged_lengths_and_resource_limits_are_rejected);
export_case!(framing_is_not_authentication);

#[unsafe(no_mangle)]
pub extern "C" fn sync_item_v1_vectors() {
    v1_cases::v1_golden_vectors();
    v1_cases::v1_bounds_and_context();
    v1_cases::v1_auth_context_and_version_refusals();
    v1_cases::v1_authenticated_frame_refusals();
}

#[unsafe(no_mangle)]
pub extern "C" fn key_vectors() {
    key_cases::rfc5869_sha256_vectors();
    key_cases::independent_document_key_vectors();
    key_cases::derived_key_isolation_and_envelope();
}

#[unsafe(no_mangle)]
pub extern "C" fn envelope_vectors() {
    independent_pte0_golden_vectors();
    published_xchacha_vector();
    envelope_roundtrip_and_context_bytes();
    envelope_rejects_mutations_and_wrong_context();
    authenticated_invalid_frame_is_rejected();
}

#[path = "../tests/amk_v1.rs"]
mod amk_cases;
#[path = "../tests/blob_v1.rs"]
mod blob_cases;
#[unsafe(no_mangle)]
pub extern "C" fn amk_v1_vectors() {
    amk_cases::official_hpke_and_argon();
    amk_cases::amk_full_vectors();
    amk_cases::amk_refusals_and_rewrap();
    amk_cases::amk_authenticated_frame_refusals();
}
#[unsafe(no_mangle)]
pub extern "C" fn blob_v1_vectors() {
    blob_cases::blob_full_vectors();
    blob_cases::blob_boundaries_and_poison();
    blob_cases::blob_authenticated_invalid_frames();
    blob_cases::blob_late_padding_and_mixed_streams();
}

#[unsafe(no_mangle)]
pub extern "C" fn argon_profile_cost(t: u32) {
    use privatale_core::amk_v1::{Context, password_key};
    let c = Context {
        owner_id: [1; 16],
        envelope_id: [2; 16],
        amk_version: 1,
        format_version: 1,
    };
    let key = password_key(&c, b"P1 synthetic password", &[3; 16], t).unwrap();
    assert_ne!(*key, [0; 32]);
}
