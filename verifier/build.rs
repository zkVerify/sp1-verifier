use std::env;
use std::fs::File;
use std::path::Path;

use executor::Program;
use p3_baby_bear::BabyBear;
use sp1_sdk::{Prover, ProverClient};

fn main() {
    build_wrap_program();
}

fn build_wrap_program() {
    let program: Program<BabyBear> = ProverClient::builder()
        .cpu()
        .build()
        .inner()
        .wrap_program()
        .into();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("wrap_program.bin");
    let mut file = File::create(dest_path).unwrap();
    bincode::serde::encode_into_std_write(&program, &mut file, bincode::config::legacy()).unwrap();
}
