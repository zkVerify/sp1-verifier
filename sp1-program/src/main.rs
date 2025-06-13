#![no_main]

use sha2::{Digest, Sha256};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let preimage: Vec<u8> = sp1_zkvm::io::read();
    let hash: [u8; 32] = Sha256::new().chain_update(&preimage).finalize().into();
    sp1_zkvm::io::commit(&hash);
}
