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

use crate::{Error, InnerSC, ShardProof, checks::*, vks::*};
use alloc::vec;
use core::borrow::Borrow;
use p3_field::Field;
use sp1_recursion_core_no_std::{air::RecursionPublicValues, machine::RecursionAir};
use sp1_stark_no_std::{MachineProof, MachineVerificationError, StarkGenericConfig};

const SHRINK_DEGREE: usize = 3;
type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE>;

pub fn verify(vkey_digest: &[u8; 32], proof: &ShardProof, inputs: &[u8]) -> Result<(), Error> {
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    if !is_public_inputs_digest_valid(public_values, inputs) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "public input hash mismatch",
        ));
    }
    if !is_vkey_digest_valid(public_values, vkey_digest) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "sp1 vk hash mismatch",
        ));
    }
    if public_values.vk_root != recursion_vk_root() {
        return Err(MachineVerificationError::InvalidPublicValues(
            "vk_root mismatch",
        ));
    }
    if !public_values.is_complete.is_one() {
        return Err(MachineVerificationError::InvalidPublicValues(
            "is_complete is not 1",
        ));
    }
    if !is_recursion_public_values_valid(&InnerSC::default(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    let shrink_machine = ShrinkAir::shrink_machine(InnerSC::compressed());
    let mut challenger = shrink_machine.config().challenger();

    shrink_machine.verify(
        &shrink_vk(),
        &MachineProof {
            shard_proofs: vec![proof.clone()],
        },
        &mut challenger,
    )
}
