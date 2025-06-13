use lazy_static::lazy_static;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};

const RC_16_30_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rc_16_30.bin"));

lazy_static! {
    static ref RC_16_30: [[BabyBear; 16]; 30] =
        bincode::serde::decode_from_slice(RC_16_30_BYTES, bincode::config::legacy())
            .unwrap()
            .0;
}

pub fn perm() -> Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>
{
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 13;
    let mut round_constants = RC_16_30.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = round_constants;
    Poseidon2::new(
        ROUNDS_F,
        external_round_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_round_constants,
        DiffusionMatrixBabyBear,
    )
}
