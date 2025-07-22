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

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod checks;
mod merkle;
mod verifier;
mod vks;

type InnerSC = sp1_stark_no_std::baby_bear_poseidon2::BabyBearPoseidon2;
pub type ShardProof = sp1_stark_no_std::ShardProof<InnerSC>;
pub type Error = sp1_stark_no_std::MachineVerificationError<InnerSC>;

pub use merkle::MerkleProof;
pub use verifier::{Proof, verify};
