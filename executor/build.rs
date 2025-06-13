use std::{env, fs::File, path::Path};

use sp1_primitives::RC_16_30;

fn main() {
    build_rc_16_30();
}

fn build_rc_16_30() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("rc_16_30.bin");
    let mut file = File::create(dest_path).unwrap();
    bincode::serde::encode_into_std_write(*RC_16_30, &mut file, bincode::config::legacy()).unwrap();
}
