use core as std; // derive macro `AlignedBorrow` in sp1-derive dependency uses std
use core::{borrow::BorrowMut, mem::MaybeUninit};

use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;

use crate::{
    DIGEST_SIZE, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS, WORD_SIZE, septic_extension::SepticCurve,
};

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Word<T>(pub [T; WORD_SIZE]);

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    pub committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [T; POSEIDON_NUM_WORDS],
    pub start_pc: T,
    pub next_pc: T,
    pub start_shard: T,
    pub next_shard: T,
    pub start_execution_shard: T,
    pub next_execution_shard: T,
    pub previous_init_addr_bits: [T; 32],
    pub last_init_addr_bits: [T; 32],
    pub previous_finalize_addr_bits: [T; 32],
    pub last_finalize_addr_bits: [T; 32],
    pub start_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],
    pub end_reconstruct_deferred_digest: [T; POSEIDON_NUM_WORDS],
    pub sp1_vk_digest: [T; DIGEST_SIZE],
    pub vk_root: [T; DIGEST_SIZE],
    pub global_cumulative_sum: SepticDigest<T>,
    pub is_complete: T,
    pub contains_execution_shard: T,
    pub exit_code: T,
    pub digest: [T; DIGEST_SIZE],
}

impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSIVE_PROOF_NUM_PV_ELTS] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSIVE_PROOF_NUM_PV_ELTS];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

#[cfg(feature = "std")]
pub mod conversions {
    use p3_field::PrimeField32;

    use super::*;
    use crate::Address;

    impl<F: PrimeField32> From<sp1_stark::Word<sp1_recursion_core::Address<F>>> for Word<Address> {
        fn from(value: sp1_stark::Word<sp1_recursion_core::Address<F>>) -> Self {
            Self(core::array::from_fn(|i| value.0[i].into()))
        }
    }

    impl<F: PrimeField32>
        From<sp1_stark::septic_digest::SepticDigest<sp1_recursion_core::Address<F>>>
        for SepticDigest<Address>
    {
        fn from(
            value: sp1_stark::septic_digest::SepticDigest<sp1_recursion_core::Address<F>>,
        ) -> Self {
            Self(value.0.into())
        }
    }

    impl<F: PrimeField32>
        From<sp1_recursion_core::air::RecursionPublicValues<sp1_recursion_core::Address<F>>>
        for RecursionPublicValues<Address>
    {
        fn from(
            value: sp1_recursion_core::air::RecursionPublicValues<sp1_recursion_core::Address<F>>,
        ) -> Self {
            Self {
                committed_value_digest: core::array::from_fn(|i| {
                    value.committed_value_digest[i].into()
                }),
                deferred_proofs_digest: core::array::from_fn(|i| {
                    value.deferred_proofs_digest[i].into()
                }),
                start_pc: value.start_pc.into(),
                next_pc: value.next_pc.into(),
                start_shard: value.start_shard.into(),
                next_shard: value.next_shard.into(),
                start_execution_shard: value.start_execution_shard.into(),
                next_execution_shard: value.next_execution_shard.into(),
                previous_init_addr_bits: core::array::from_fn(|i| {
                    value.previous_init_addr_bits[i].into()
                }),
                last_init_addr_bits: core::array::from_fn(|i| value.last_init_addr_bits[i].into()),
                previous_finalize_addr_bits: core::array::from_fn(|i| {
                    value.previous_finalize_addr_bits[i].into()
                }),
                last_finalize_addr_bits: core::array::from_fn(|i| {
                    value.last_finalize_addr_bits[i].into()
                }),
                start_reconstruct_deferred_digest: core::array::from_fn(|i| {
                    value.start_reconstruct_deferred_digest[i].into()
                }),
                end_reconstruct_deferred_digest: core::array::from_fn(|i| {
                    value.end_reconstruct_deferred_digest[i].into()
                }),
                sp1_vk_digest: core::array::from_fn(|i| value.sp1_vk_digest[i].into()),
                vk_root: core::array::from_fn(|i| value.vk_root[i].into()),
                global_cumulative_sum: value.global_cumulative_sum.into(),
                is_complete: value.is_complete.into(),
                contains_execution_shard: value.contains_execution_shard.into(),
                exit_code: value.exit_code.into(),
                digest: core::array::from_fn(|i| value.digest[i].into()),
            }
        }
    }
}
