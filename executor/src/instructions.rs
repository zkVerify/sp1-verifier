use crate::{Block, D, PERMUTATION_WIDTH, public_values::RecursionPublicValues};
use alloc::{boxed::Box, vec::Vec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program<F> {
    #[serde(bound(
        serialize = "Block<F>: Serialize",
        deserialize = "Block<F>: DeserializeOwned"
    ))]
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction<F> {
    BaseAlu(BaseAluInstr),
    ExtAlu(ExtAluInstr),
    #[serde(bound(
        serialize = "Block<F>: Serialize",
        deserialize = "Block<F>: DeserializeOwned"
    ))]
    Mem(MemInstr<F>),
    Poseidon2(Box<Poseidon2SkinnyInstr>),
    Select(SelectInstr),
    ExpReverseBitsLen(ExpReverseBitsInstr),
    HintBits(HintBitsInstr),
    HintAddCurve(Box<HintAddCurveInstr>),
    BatchFRI(Box<BatchFRIInstr>),
    HintExt2Felts(HintExt2FeltsInstr),
    CommitPublicValues(Box<CommitPublicValuesInstr>),
    Hint(HintInstr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(transparent)]
pub struct Address(pub usize);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluInstr {
    pub opcode: BaseAluOpcode,
    pub addrs: BaseAluIo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum BaseAluOpcode {
    AddF,
    SubF,
    MulF,
    DivF,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluIo {
    pub out: Address,
    pub in1: Address,
    pub in2: Address,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluInstr {
    pub opcode: ExtAluOpcode,
    pub addrs: ExtAluIo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub enum ExtAluOpcode {
    AddE,
    SubE,
    MulE,
    DivE,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluIo {
    pub out: Address,
    pub in1: Address,
    pub in2: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemIo<V> {
    pub inner: V,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address>,
    #[serde(bound(
        serialize = "Block<F>: Serialize",
        deserialize = "Block<F>: DeserializeOwned"
    ))]
    pub vals: MemIo<Block<F>>,
    pub kind: MemAccessKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2Io {
    pub input: [Address; PERMUTATION_WIDTH],
    pub output: [Address; PERMUTATION_WIDTH],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2SkinnyInstr {
    pub addrs: Poseidon2Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectIo {
    pub bit: Address,
    pub out1: Address,
    pub out2: Address,
    pub in1: Address,
    pub in2: Address,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectInstr {
    pub addrs: SelectIo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsIo {
    pub base: Address,
    pub exp: Vec<Address>,
    pub result: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpReverseBitsInstr {
    pub addrs: ExpReverseBitsIo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintBitsInstr {
    pub output_addrs: Vec<Address>,
    pub input_addr: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintAddCurveInstr {
    pub output_x_addrs: Vec<Address>,
    pub output_y_addrs: Vec<Address>,
    pub input1_x_addrs: Vec<Address>,
    pub input1_y_addrs: Vec<Address>,
    pub input2_x_addrs: Vec<Address>,
    pub input2_y_addrs: Vec<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtSingleIo {
    pub acc: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtVecIo {
    pub p_at_z: Vec<Address>,
    pub alpha_pow: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIBaseVecIo {
    pub p_at_x: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIInstr {
    pub base_vec_addrs: BatchFRIBaseVecIo,
    pub ext_single_addrs: BatchFRIExtSingleIo,
    pub ext_vec_addrs: BatchFRIExtVecIo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintExt2FeltsInstr {
    pub output_addrs: [Address; D],
    pub input_addr: Address,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CommitPublicValuesInstr {
    pub pv_addrs: RecursionPublicValues<Address>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintInstr {
    pub output_addrs: Vec<Address>,
}

#[cfg(feature = "std")]
pub mod conversions {
    use super::*;
    use core::array;
    use p3_field::PrimeField32;
    use sp1_recursion_core::{self as sp1rc, Instruction as SP1Instruction};
    use std::sync::Arc;

    impl<F: PrimeField32> From<Arc<sp1rc::RecursionProgram<F>>> for Program<F> {
        fn from(value: Arc<sp1rc::RecursionProgram<F>>) -> Self {
            Self {
                instructions: value
                    .inner
                    .iter()
                    .filter(|instr| match instr {
                        SP1Instruction::Print(_) => false,
                        SP1Instruction::DebugBacktrace(_) => false,
                        _ => true,
                    })
                    .map(|i| i.clone().into())
                    .collect(),
                total_memory: value.total_memory,
            }
        }
    }

    impl<F: PrimeField32> From<SP1Instruction<F>> for Instruction<F> {
        fn from(value: SP1Instruction<F>) -> Self {
            match value {
                SP1Instruction::BaseAlu(instr) => Instruction::BaseAlu(instr.into()),
                SP1Instruction::ExtAlu(instr) => Instruction::ExtAlu(instr.into()),
                SP1Instruction::Mem(instr) => Instruction::Mem(instr.into()),
                SP1Instruction::Poseidon2(instr) => {
                    Instruction::Poseidon2(Box::new((*instr.to_owned()).into()))
                }
                SP1Instruction::Select(instr) => Instruction::Select(instr.into()),
                SP1Instruction::ExpReverseBitsLen(instr) => {
                    Instruction::ExpReverseBitsLen(instr.into())
                }
                SP1Instruction::HintBits(instr) => Instruction::HintBits(instr.into()),
                SP1Instruction::HintAddCurve(instr) => {
                    Instruction::HintAddCurve(Box::new((*instr.to_owned()).into()))
                }
                SP1Instruction::BatchFRI(instr) => {
                    Instruction::BatchFRI(Box::new((*instr.to_owned()).into()))
                }
                SP1Instruction::HintExt2Felts(instr) => Instruction::HintExt2Felts(instr.into()),
                SP1Instruction::CommitPublicValues(instr) => {
                    Instruction::CommitPublicValues(Box::new((*instr.to_owned()).into()))
                }
                SP1Instruction::Hint(instr) => Instruction::Hint(instr.into()),
                SP1Instruction::FriFold(_) => unimplemented!(),
                SP1Instruction::Print(_) => unimplemented!(),
                _ => unimplemented!(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::Address<F>> for Address {
        fn from(value: sp1rc::Address<F>) -> Self {
            Self(value.as_usize())
        }
    }

    impl<F: PrimeField32> From<sp1rc::BaseAluInstr<F>> for BaseAluInstr {
        fn from(value: sp1rc::BaseAluInstr<F>) -> Self {
            Self {
                opcode: value.opcode.into(),
                addrs: value.addrs.into(),
            }
        }
    }

    impl From<sp1rc::BaseAluOpcode> for BaseAluOpcode {
        fn from(value: sp1rc::BaseAluOpcode) -> Self {
            match value {
                sp1rc::BaseAluOpcode::AddF => Self::AddF,
                sp1rc::BaseAluOpcode::SubF => Self::SubF,
                sp1rc::BaseAluOpcode::MulF => Self::MulF,
                sp1rc::BaseAluOpcode::DivF => Self::DivF,
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::BaseAluIo<sp1rc::Address<F>>> for BaseAluIo {
        fn from(value: sp1rc::BaseAluIo<sp1rc::Address<F>>) -> Self {
            Self {
                out: value.out.into(),
                in1: value.in1.into(),
                in2: value.in2.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::ExtAluInstr<F>> for ExtAluInstr {
        fn from(value: sp1rc::ExtAluInstr<F>) -> Self {
            Self {
                opcode: value.opcode.into(),
                addrs: value.addrs.into(),
            }
        }
    }

    impl From<sp1rc::ExtAluOpcode> for ExtAluOpcode {
        fn from(value: sp1rc::ExtAluOpcode) -> Self {
            match value {
                sp1rc::ExtAluOpcode::AddE => Self::AddE,
                sp1rc::ExtAluOpcode::SubE => Self::SubE,
                sp1rc::ExtAluOpcode::MulE => Self::MulE,
                sp1rc::ExtAluOpcode::DivE => Self::DivE,
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::ExtAluIo<sp1rc::Address<F>>> for ExtAluIo {
        fn from(value: sp1rc::ExtAluIo<sp1rc::Address<F>>) -> Self {
            Self {
                out: value.out.into(),
                in1: value.in1.into(),
                in2: value.in2.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::MemIo<sp1rc::Address<F>>> for MemIo<Address> {
        fn from(value: sp1rc::MemIo<sp1rc::Address<F>>) -> Self {
            Self {
                inner: value.inner.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::MemIo<sp1rc::air::Block<F>>> for MemIo<Block<F>> {
        fn from(value: sp1rc::MemIo<sp1rc::air::Block<F>>) -> Self {
            Self {
                inner: value.inner.into(),
            }
        }
    }

    impl From<sp1rc::MemAccessKind> for MemAccessKind {
        fn from(value: sp1rc::MemAccessKind) -> Self {
            match value {
                sp1rc::MemAccessKind::Read => Self::Read,
                sp1rc::MemAccessKind::Write => Self::Write,
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::MemInstr<F>> for MemInstr<F> {
        fn from(value: sp1rc::MemInstr<F>) -> Self {
            Self {
                addrs: value.addrs.into(),
                vals: value.vals.into(),
                kind: value.kind.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::Poseidon2Io<sp1rc::Address<F>>> for Poseidon2Io {
        fn from(value: sp1rc::Poseidon2Io<sp1rc::Address<F>>) -> Self {
            Self {
                input: array::from_fn(|i| value.input[i].into()),
                output: array::from_fn(|i| value.output[i].into()),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::Poseidon2SkinnyInstr<F>> for Poseidon2SkinnyInstr {
        fn from(value: sp1rc::Poseidon2SkinnyInstr<F>) -> Self {
            Self {
                addrs: value.addrs.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::SelectIo<sp1rc::Address<F>>> for SelectIo {
        fn from(value: sp1rc::SelectIo<sp1rc::Address<F>>) -> Self {
            Self {
                bit: value.bit.into(),
                out1: value.out1.into(),
                out2: value.out2.into(),
                in1: value.in1.into(),
                in2: value.in2.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::SelectInstr<F>> for SelectInstr {
        fn from(value: sp1rc::SelectInstr<F>) -> Self {
            Self {
                addrs: value.addrs.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::ExpReverseBitsIo<sp1rc::Address<F>>> for ExpReverseBitsIo {
        fn from(value: sp1rc::ExpReverseBitsIo<sp1rc::Address<F>>) -> Self {
            Self {
                base: value.base.into(),
                exp: value.exp.into_iter().map(|a| a.into()).collect(),
                result: value.result.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::ExpReverseBitsInstr<F>> for ExpReverseBitsInstr {
        fn from(value: sp1rc::ExpReverseBitsInstr<F>) -> Self {
            Self {
                addrs: value.addrs.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::instruction::HintBitsInstr<F>> for HintBitsInstr {
        fn from(value: sp1rc::instruction::HintBitsInstr<F>) -> Self {
            Self {
                output_addrs: value
                    .output_addrs_mults
                    .into_iter()
                    .map(|(a, _)| a.into())
                    .collect(),
                input_addr: value.input_addr.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::instruction::HintAddCurveInstr<F>> for HintAddCurveInstr {
        fn from(value: sp1rc::instruction::HintAddCurveInstr<F>) -> Self {
            Self {
                output_x_addrs: value
                    .output_x_addrs_mults
                    .into_iter()
                    .map(|(a, _)| a.into())
                    .collect(),
                output_y_addrs: value
                    .output_y_addrs_mults
                    .into_iter()
                    .map(|(a, _)| a.into())
                    .collect(),
                input1_x_addrs: value.input1_x_addrs.into_iter().map(|a| a.into()).collect(),
                input1_y_addrs: value.input1_y_addrs.into_iter().map(|a| a.into()).collect(),
                input2_x_addrs: value.input2_x_addrs.into_iter().map(|a| a.into()).collect(),
                input2_y_addrs: value.input2_y_addrs.into_iter().map(|a| a.into()).collect(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::BatchFRIExtSingleIo<sp1rc::Address<F>>> for BatchFRIExtSingleIo {
        fn from(value: sp1rc::BatchFRIExtSingleIo<sp1rc::Address<F>>) -> Self {
            Self {
                acc: value.acc.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::BatchFRIExtVecIo<Vec<sp1rc::Address<F>>>> for BatchFRIExtVecIo {
        fn from(value: sp1rc::BatchFRIExtVecIo<Vec<sp1rc::Address<F>>>) -> Self {
            Self {
                p_at_z: value.p_at_z.into_iter().map(|a| a.into()).collect(),
                alpha_pow: value.alpha_pow.into_iter().map(|a| a.into()).collect(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::BatchFRIBaseVecIo<Vec<sp1rc::Address<F>>>> for BatchFRIBaseVecIo {
        fn from(value: sp1rc::BatchFRIBaseVecIo<Vec<sp1rc::Address<F>>>) -> Self {
            Self {
                p_at_x: value.p_at_x.into_iter().map(|a| a.into()).collect(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::BatchFRIInstr<F>> for BatchFRIInstr {
        fn from(value: sp1rc::BatchFRIInstr<F>) -> Self {
            Self {
                base_vec_addrs: value.base_vec_addrs.into(),
                ext_single_addrs: value.ext_single_addrs.into(),
                ext_vec_addrs: value.ext_vec_addrs.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::instruction::HintExt2FeltsInstr<F>> for HintExt2FeltsInstr {
        fn from(value: sp1rc::instruction::HintExt2FeltsInstr<F>) -> Self {
            Self {
                output_addrs: array::from_fn(|i| value.output_addrs_mults[i].0.into()),
                input_addr: value.input_addr.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::CommitPublicValuesInstr<F>> for CommitPublicValuesInstr {
        fn from(value: sp1rc::CommitPublicValuesInstr<F>) -> Self {
            Self {
                pv_addrs: value.pv_addrs.into(),
            }
        }
    }

    impl<F: PrimeField32> From<sp1rc::instruction::HintInstr<F>> for HintInstr {
        fn from(value: sp1rc::instruction::HintInstr<F>) -> Self {
            Self {
                output_addrs: value
                    .output_addrs_mults
                    .into_iter()
                    .map(|(a, _)| a.into())
                    .collect(),
            }
        }
    }
}
