use crate::InnerSC;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

type StarkVerifyingKey = sp1_stark_no_std::StarkVerifyingKey<InnerSC>;

const DIGEST_SIZE: usize = 8;
const SHRINK_VK_BYTES: &[u8] = include_bytes!("../resources/vk.bin");

pub fn shrink_vk() -> StarkVerifyingKey {
    bincode::serde::decode_from_slice(SHRINK_VK_BYTES, bincode::config::legacy())
        .unwrap()
        .0
}

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
mod deserialization {

    use super::SHRINK_VK_BYTES;
    use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    use sp1_stark::SP1ProverOpts;

    #[ignore]
    #[test]
    fn shrink_vk_is_correct() {
        const SP1_ELF: &[u8] = include_bytes!("../resources/sp1-program");
        let mut stdin = SP1Stdin::new();
        stdin.write(&b"hello world".to_vec());

        let prover = ProverClient::builder().cpu().build();
        let (pk, _vk) = prover.setup(SP1_ELF);

        let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();

        let shrinked_proof = prover
            .inner()
            .shrink(
                *proof.proof.try_as_compressed().unwrap(),
                SP1ProverOpts::default(),
            )
            .unwrap();

        let shrink_vk_bytes =
            bincode::serde::encode_to_vec(&shrinked_proof.vk, bincode::config::legacy()).unwrap();

        prover.inner().recursion_vk_root;

        assert_eq!(SHRINK_VK_BYTES, &shrink_vk_bytes[..]);
    }
}
