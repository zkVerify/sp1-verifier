#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod checks;
mod verifier;
mod vks;

type InnerSC = sp1_stark_no_std::baby_bear_poseidon2::BabyBearPoseidon2;
pub type ShardProof = sp1_stark_no_std::ShardProof<InnerSC>;
pub type Error = sp1_stark_no_std::MachineVerificationError<InnerSC>;

pub use verifier::verify;
