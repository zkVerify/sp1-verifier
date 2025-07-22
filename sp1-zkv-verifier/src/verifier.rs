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

use crate::{Error, InnerSC, ShardProof, checks::*, merkle::*, vks::*};
use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, fmt::Debug};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, TwoAdicField};
use serde::{Deserialize, Serialize};
use sp1_primitives::poseidon2_hash;
use sp1_recursion_core_no_std::machine::RecursionAir;
use sp1_stark_no_std::{
    DIGEST_SIZE, MachineProof, MachineVerificationError, StarkGenericConfig, StarkVerifyingKey,
};

const SHRINK_DEGREE: usize = 3;
type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub shard_proof: ShardProof,
    pub vk: StarkVerifyingKey<InnerSC>,
    pub vk_merkle_proof: MerkleProof,
}

pub fn verify(vkey_digest: &[u8; 32], proof: &Proof, inputs: &[u8]) -> Result<(), Error> {
    let Proof {
        shard_proof,
        vk: recursion_vkey,
        vk_merkle_proof,
    } = proof;

    let public_values = shard_proof.public_values.as_slice().borrow();

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
    if !is_merkle_path_valid(
        vk_merkle_proof,
        hash_babybear(recursion_vkey),
        recursion_vk_root(),
    ) {
        return Err(MachineVerificationError::InvalidVerificationKey);
    }

    let shrink_machine = ShrinkAir::shrink_machine(InnerSC::compressed());
    let mut challenger = shrink_machine.config().challenger();

    shrink_machine.verify(
        recursion_vkey,
        &MachineProof {
            shard_proofs: vec![shard_proof.clone()],
        },
        &mut challenger,
    )
}

fn hash_babybear(vk: &StarkVerifyingKey<InnerSC>) -> [BabyBear; DIGEST_SIZE] {
    let mut num_inputs = DIGEST_SIZE + 1 + 14 + (7 * vk.chip_information.len());
    for (name, _, _) in vk.chip_information.iter() {
        num_inputs += name.len();
    }
    let mut inputs = Vec::with_capacity(num_inputs);
    inputs.extend(vk.commit.as_ref());
    inputs.push(vk.pc_start);
    inputs.extend(vk.initial_global_cumulative_sum.0.x.0);
    inputs.extend(vk.initial_global_cumulative_sum.0.y.0);
    for (name, domain, dimension) in vk.chip_information.iter() {
        inputs.push(BabyBear::from_canonical_usize(domain.log_n));
        let size = 1 << domain.log_n;
        inputs.push(BabyBear::from_canonical_usize(size));
        let g = BabyBear::two_adic_generator(domain.log_n);
        inputs.push(domain.shift);
        inputs.push(g);
        inputs.push(BabyBear::from_canonical_usize(dimension.width));
        inputs.push(BabyBear::from_canonical_usize(dimension.height));
        inputs.push(BabyBear::from_canonical_usize(name.len()));
        for byte in name.as_bytes() {
            inputs.push(BabyBear::from_canonical_u8(*byte));
        }
    }

    poseidon2_hash(inputs)
}
