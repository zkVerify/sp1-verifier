use alloc::vec::Vec;
use core::fmt::Debug;
use p3_baby_bear::BabyBear;
use p3_symmetric::Permutation;
use p3_util::reverse_bits_len;
use serde::{Deserialize, Serialize};
use sp1_stark_no_std::{DIGEST_SIZE, inner_perm};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: usize,
    pub path: Vec<[BabyBear; DIGEST_SIZE]>,
}

fn constant_compress(input: [[BabyBear; DIGEST_SIZE]; 2]) -> [BabyBear; DIGEST_SIZE] {
    let mut pre_iter = input.into_iter().flatten();
    let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
    inner_perm().permute_mut(&mut pre);
    pre[..8].try_into().unwrap()
}

pub fn is_merkle_path_valid(
    proof: &MerkleProof,
    mut value: [BabyBear; DIGEST_SIZE],
    commitment: [BabyBear; DIGEST_SIZE],
) -> bool {
    let MerkleProof { index, path } = proof;

    let mut index = reverse_bits_len(*index, path.len());

    for &sibling in path {
        let new_pair = if index % 2 == 0 {
            [value, sibling]
        } else {
            [sibling, value]
        };
        value = constant_compress(new_pair);
        index >>= 1;
    }

    value == commitment
}
