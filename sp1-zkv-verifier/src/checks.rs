use crate::InnerSC;
use alloc::vec::Vec;
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32};
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha256};
use sp1_recursion_core_no_std::air::{NUM_PV_ELMS_TO_HASH, RecursionPublicValues};
use sp1_stark_no_std::InnerHash;

/// Check if the digest of the public values is correct.
pub fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

pub fn is_public_inputs_digest_valid(
    recursion_public_values: &RecursionPublicValues<BabyBear>,
    public_inputs: &[u8],
) -> bool {
    let committed_value_digest_bytes: [u8; 32] = recursion_public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect_vec()
        .try_into()
        .unwrap();

    let blake3_input_hash = blake3::hash(public_inputs);
    let sha256_input_hash = Sha256::digest(public_inputs);

    sha256_input_hash == committed_value_digest_bytes.into()
        || blake3_input_hash == committed_value_digest_bytes
}

pub fn is_vkey_digest_valid(
    recursion_public_values: &RecursionPublicValues<BabyBear>,
    vkey_digest: &[u8; 32],
) -> bool {
    let vkey_hash: [BabyBear; 8] = vkey_digest
        .chunks_exact(4)
        .map(|bytes| BabyBear::from_canonical_u32(u32::from_le_bytes(bytes.try_into().unwrap())))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    recursion_public_values.sp1_vk_digest == vkey_hash
}
