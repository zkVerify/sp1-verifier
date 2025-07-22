// Copyright 2025, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_stark_no_std::DIGEST_SIZE;

pub fn recursion_vk_root() -> [BabyBear; DIGEST_SIZE] {
    [
        779620665u32,
        657361014,
        1275916220,
        1016544356,
        761269804,
        102002516,
        650304731,
        1117171342,
    ]
    .map(BabyBear::from_canonical_u32)
}

#[cfg(test)]
mod tests {
    use sp1_sdk::{Prover, ProverClient};

    use super::*;

    #[test]
    fn recursion_vk_root_is_correct() {
        let prover = ProverClient::builder().cpu().build();
        let expected_vk = prover
            .inner()
            .recursion_vk_root
            .map(|el| p3_field_original::PrimeField32::as_canonical_u32(&el));
        let actual_vk = recursion_vk_root().map(|el| p3_field::PrimeField32::as_canonical_u32(&el));
        assert_eq!(actual_vk, expected_vk)
    }
}
