#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod block;
mod constants;
mod instructions;
mod perm;
mod public_values;
mod septic_extension;

use alloc::{collections::VecDeque, vec::Vec};
use constants::*;
use core::{
    borrow::Borrow,
    iter::zip,
    marker::PhantomData,
    ops::{Index, IndexMut},
};
use p3_field::{AbstractExtensionField, ExtensionField, PrimeField32, PrimeField64};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicPermutation, Permutation};
use p3_util::reverse_bits_len;
use septic_extension::*;

pub use block::*;
pub use instructions::*;
pub use perm::*;
pub use public_values::*;

type Perm<F, Diffusion> = Poseidon2<
    F,
    Poseidon2ExternalMatrixGeneral,
    Diffusion,
    PERMUTATION_WIDTH,
    POSEIDON2_SBOX_DEGREE,
>;

#[derive(Clone, Default, Debug)]
pub struct Memory<F>(Vec<Block<F>>);

impl<F: PrimeField64> Memory<F> {
    pub fn resize_with_zeros(&mut self, len: usize) {
        self.0.resize_with(len, || Block::from(F::zero()));
    }
}

impl<F> Index<Address> for Memory<F> {
    type Output = Block<F>;
    fn index(&self, index: Address) -> &Self::Output {
        &self.0[index.0]
    }
}

impl<F> IndexMut<Address> for Memory<F> {
    fn index_mut(&mut self, index: Address) -> &mut Self::Output {
        &mut self.0[index.0]
    }
}

pub struct Executor<F, EF, Diffusion> {
    pub memory: Memory<F>,
    pub witness_stream: VecDeque<Block<F>>,
    pub perm: Perm<F, Diffusion>,
    pub public_values: Option<RecursionPublicValues<F>>,
    _marker_ef: PhantomData<EF>,
}

impl<F: Default, EF, Diffusion> Executor<F, EF, Diffusion> {
    pub fn new(perm: Perm<F, Diffusion>) -> Self {
        Self {
            memory: Default::default(),
            witness_stream: Default::default(),
            perm,
            public_values: None,
            _marker_ef: PhantomData,
        }
    }
}

impl<F: PrimeField32, EF: ExtensionField<F>, Diffusion> Executor<F, EF, Diffusion>
where
    Poseidon2<
        F,
        Poseidon2ExternalMatrixGeneral,
        Diffusion,
        PERMUTATION_WIDTH,
        POSEIDON2_SBOX_DEGREE,
    >: CryptographicPermutation<[F; PERMUTATION_WIDTH]>,
{
    pub fn execute(&mut self, program: &Program<F>) {
        self.memory.resize_with_zeros(program.total_memory);

        for instruction in program.instructions.iter() {
            match instruction {
                Instruction::BaseAlu(instr) => self.base_alu(instr),
                Instruction::ExtAlu(instr) => self.ext_alu(instr),
                Instruction::Mem(instr) => self.mem(instr),
                Instruction::Poseidon2(instr) => self.poseidon2(&instr),
                Instruction::Select(instr) => self.select(instr),
                Instruction::ExpReverseBitsLen(instr) => self.exp_reverse_bits_len(instr),
                Instruction::HintBits(instr) => self.hint_bits(instr),
                Instruction::HintAddCurve(instr) => self.hint_add_curve(instr),
                Instruction::BatchFRI(instr) => self.batch_fri(instr),
                Instruction::HintExt2Felts(instr) => self.hint_ext2felts(instr),
                Instruction::CommitPublicValues(instr) => self.commit_public_values(instr),
                Instruction::Hint(instr) => self.hint(instr),
            }
        }
    }

    fn base_alu(&mut self, instr: &BaseAluInstr) {
        let BaseAluIo { in1, in2, out } = instr.addrs;
        let in1_f = self.memory[in1][0];
        let in2_f = self.memory[in2][0];
        let res = match instr.opcode {
            BaseAluOpcode::AddF => in1_f + in2_f,
            BaseAluOpcode::SubF => in1_f - in2_f,
            BaseAluOpcode::MulF => in1_f * in2_f,
            BaseAluOpcode::DivF => match in1_f.try_div(in2_f) {
                Some(x) => x,
                None => {
                    if in1_f.is_zero() {
                        F::one()
                    } else {
                        panic!("Division by zero")
                    }
                }
            },
        };
        self.memory[out] = res.into();
    }

    fn ext_alu(&mut self, instr: &ExtAluInstr) {
        let ExtAluIo { in1, in2, out } = instr.addrs;
        let in1_ef = EF::from_base_slice(&self.memory[in1].0);
        let in2_ef = EF::from_base_slice(&self.memory[in2].0);
        let res = match instr.opcode {
            ExtAluOpcode::AddE => in1_ef + in2_ef,
            ExtAluOpcode::SubE => in1_ef - in2_ef,
            ExtAluOpcode::MulE => in1_ef * in2_ef,
            ExtAluOpcode::DivE => match in1_ef.try_div(in2_ef) {
                Some(x) => x,
                None => {
                    if in1_ef.is_zero() {
                        EF::one()
                    } else {
                        panic!("Division by zero")
                    }
                }
            },
        };
        self.memory[out] = res.as_base_slice().into();
    }

    fn mem(&mut self, instr: &MemInstr<F>) {
        let &MemInstr {
            addrs: MemIo { inner: addr },
            vals: MemIo { inner: val },
            kind,
        } = instr;
        match kind {
            MemAccessKind::Read => assert_eq!(self.memory[addr], val),
            MemAccessKind::Write => self.memory[addr] = val,
        }
    }

    fn poseidon2(&mut self, instr: &Poseidon2SkinnyInstr) {
        let &Poseidon2SkinnyInstr {
            addrs: Poseidon2Io { input, output },
        } = instr;
        let in_vals = core::array::from_fn(|i| self.memory[input[i]][0]);
        let perm_output = self.perm.permute(in_vals);

        perm_output.iter().zip(output).for_each(|(&val, addr)| {
            self.memory[addr] = val.into();
        });
    }

    fn select(&mut self, instr: &SelectInstr) {
        let &SelectInstr {
            addrs:
                SelectIo {
                    bit,
                    out1,
                    out2,
                    in1,
                    in2,
                },
        } = instr;

        let bit_f = self.memory[bit][0];
        let in1_f = self.memory[in1][0];
        let in2_f = self.memory[in2][0];
        let (out1_res, out2_res) = if bit_f.is_zero() {
            (in1_f, in2_f)
        } else {
            (in2_f, in1_f)
        };
        self.memory[out1] = out1_res.into();
        self.memory[out2] = out2_res.into();
    }

    fn exp_reverse_bits_len(&mut self, instr: &ExpReverseBitsInstr) {
        let ExpReverseBitsInstr {
            addrs: ExpReverseBitsIo { base, exp, result },
        } = instr;

        let base_f = self.memory[*base][0];
        let exp_bits: Vec<_> = exp.iter().map(|&x| self.memory[x][0]).collect();
        let exp_val = exp_bits
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
        let res = base_f.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
        self.memory[*result] = res.into();
    }

    fn hint_bits(&mut self, instr: &HintBitsInstr) {
        let HintBitsInstr {
            output_addrs,
            input_addr,
        } = instr;
        let input_f = self.memory[*input_addr][0].as_canonical_u32();
        let bits: Vec<_> = (0..output_addrs.len())
            .map(|i| Block::from(F::from_canonical_u32((input_f >> i) & 1)))
            .collect();
        for (bit, addr) in bits.into_iter().zip(output_addrs) {
            self.memory[*addr] = bit;
        }
    }

    fn hint_add_curve(&mut self, instr: &HintAddCurveInstr) {
        let HintAddCurveInstr {
            output_x_addrs,
            output_y_addrs,
            input1_x_addrs,
            input1_y_addrs,
            input2_x_addrs,
            input2_y_addrs,
        } = instr;
        let input1_x = SepticExtension::<F>::from_base_fn(|i| self.memory[input1_x_addrs[i]][0]);
        let input1_y = SepticExtension::<F>::from_base_fn(|i| self.memory[input1_y_addrs[i]][0]);
        let input2_x = SepticExtension::<F>::from_base_fn(|i| self.memory[input2_x_addrs[i]][0]);
        let input2_y = SepticExtension::<F>::from_base_fn(|i| self.memory[input2_y_addrs[i]][0]);
        let point1 = SepticCurve {
            x: input1_x,
            y: input1_y,
        };
        let point2 = SepticCurve {
            x: input2_x,
            y: input2_y,
        };
        let output = point1.add_incomplete(point2);
        for (val, addr) in output.x.0.into_iter().zip(output_x_addrs) {
            self.memory[*addr] = val.into();
        }
        for (val, addr) in output.y.0.into_iter().zip(output_y_addrs) {
            self.memory[*addr] = val.into();
        }
    }

    fn batch_fri(&mut self, instr: &BatchFRIInstr) {
        let BatchFRIInstr {
            base_vec_addrs: BatchFRIBaseVecIo { p_at_x },
            ext_single_addrs: BatchFRIExtSingleIo { acc },
            ext_vec_addrs: BatchFRIExtVecIo { p_at_z, alpha_pow },
        } = instr;
        let p_at_x_v: Vec<_> = p_at_x.iter().map(|&addr| self.memory[addr][0]).collect();
        let p_at_z_v: Vec<_> = p_at_z
            .iter()
            .map(|&addr| EF::from_base_slice(&self.memory[addr].0))
            .collect();
        let alpha_pow_v: Vec<_> = alpha_pow
            .iter()
            .map(|&addr| EF::from_base_slice(&self.memory[addr].0))
            .collect();
        let mut acc_v = EF::zero();
        for m in 0..p_at_z.len() {
            acc_v += alpha_pow_v[m] * (p_at_z_v[m] - EF::from_base(p_at_x_v[m]));
        }
        self.memory[*acc] = Block::from(acc_v.as_base_slice())
    }

    fn commit_public_values(&mut self, instr: &CommitPublicValuesInstr) {
        let pv_addrs = instr.pv_addrs.as_array();
        let pv_values: [F; RECURSIVE_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| self.memory[pv_addrs[i]][0]);
        self.public_values = Some(*pv_values.as_slice().borrow());
    }

    fn hint_ext2felts(&mut self, instr: &HintExt2FeltsInstr) {
        let &HintExt2FeltsInstr {
            output_addrs,
            input_addr,
        } = instr;
        let fs = self.memory[input_addr];
        for (f, addr) in fs.0.into_iter().zip(output_addrs) {
            self.memory[addr] = f.into();
        }
    }

    fn hint(&mut self, instr: &HintInstr) {
        let HintInstr { output_addrs } = instr;

        if self.witness_stream.len() < output_addrs.len() {
            panic!("empty witness stream");
        }
        let witness = self.witness_stream.drain(0..output_addrs.len());
        for (addr, val) in zip(output_addrs, witness) {
            self.memory[*addr] = val;
        }
    }
}

#[cfg(test)]
mod tests {}
