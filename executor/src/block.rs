use core::ops::{Index, IndexMut};

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

use crate::constants::D;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Block<T>(pub [T; D]);

#[cfg(feature = "std")]
impl<T> From<sp1_recursion_core::air::Block<T>> for Block<T> {
    fn from(value: sp1_recursion_core::air::Block<T>) -> Self {
        Self(value.0.into())
    }
}

impl<T> From<[T; D]> for Block<T> {
    fn from(arr: [T; D]) -> Self {
        Self(arr)
    }
}

impl<T: AbstractField> From<T> for Block<T> {
    fn from(value: T) -> Self {
        Self([value, T::zero(), T::zero(), T::zero()])
    }
}

impl<T: Copy> From<&[T]> for Block<T> {
    fn from(slice: &[T]) -> Self {
        let arr: [T; D] = slice.try_into().unwrap();
        Self(arr)
    }
}

impl<T, I> Index<I> for Block<T>
where
    [T]: Index<I>,
{
    type Output = <[T] as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.0, index)
    }
}

impl<T, I> IndexMut<I> for Block<T>
where
    [T]: IndexMut<I>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.0, index)
    }
}

impl<T> IntoIterator for Block<T> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<&[u32; 4]> for Block<BabyBear> {
    fn from(value: &[u32; 4]) -> Self {
        let arr: [BabyBear; 4] = core::array::from_fn(|i| BabyBear::from_canonical_u32(value[i]))
            .try_into()
            .unwrap();
        Self::from(arr)
    }
}

mod serialization {
    use super::*;

    use p3_baby_bear::BabyBear;
    use p3_field::{Field, PrimeField32};
    use serde::{
        Deserialize, Serialize,
        de::{SeqAccess, Visitor},
        ser::SerializeTuple,
    };

    pub const U32_MSB_MASK: u32 = 1 << 31;

    impl Serialize for Block<BabyBear> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            if self.0[1..].iter().all(|el| el.is_zero()) {
                let mut tuple = serializer.serialize_tuple(1)?;
                tuple.serialize_element(&(self.0[0].as_canonical_u32() ^ U32_MSB_MASK))?;
                tuple.end()
            } else {
                let mut tuple = serializer.serialize_tuple(4)?;
                for el in self.0.iter() {
                    tuple.serialize_element(&el.as_canonical_u32())?;
                }
                tuple.end()
            }
        }
    }

    impl<'de> Deserialize<'de> for Block<BabyBear> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct BlockVisitor;

            impl<'de> Visitor<'de> for BlockVisitor {
                type Value = Block<BabyBear>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a Block<BabyBear>")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let first_u32: u32 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                    if first_u32 & U32_MSB_MASK != 0 {
                        Ok(Block::from(BabyBear::from_canonical_u32(
                            first_u32 ^ U32_MSB_MASK,
                        )))
                    } else {
                        let mut arr = [0u32; 4];
                        arr[0] = first_u32;
                        for i in 1..=3 {
                            arr[i] = seq
                                .next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                        }
                        Ok(Block::from(core::array::from_fn(|i| {
                            BabyBear::from_canonical_u32(arr[i])
                        })))
                    }
                }
            }

            deserializer.deserialize_tuple(4, BlockVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;
    use p3_field::PrimeField32;
    use rstest::rstest;
    use serde_test::{Token, assert_tokens};

    #[rstest]
    #[case(Block::from(BabyBear::from_canonical_u32(0)))]
    #[case(Block::from(BabyBear::from_canonical_u32(1)))]
    #[case(Block::from(BabyBear::from_canonical_u32(42)))]
    #[case(Block::from(BabyBear::from_canonical_u32(BabyBear::ORDER_U32 - 1)))]
    fn ser_simple(#[case] block: Block<BabyBear>) {
        assert_tokens(
            &block,
            &[
                Token::Tuple { len: 1 },
                Token::U32(block.0[0].as_canonical_u32() ^ serialization::U32_MSB_MASK),
                Token::TupleEnd,
            ],
        );
    }

    #[rstest]
    #[case(Block::from(&[1, 2, 3, 4]))]
    #[case(Block::from(&[42, 1, 0, 0]))]
    #[case(Block::from(&[42, 0, 0, 1]))]
    #[case(Block::from(&[0, 1, 0, 0]))]
    #[case(Block::from(&[0, 0, 1, 0]))]
    #[case(Block::from(&[0, 0, 0, 1]))]
    fn ser_block(#[case] block: Block<BabyBear>) {
        let u32_tokens: Vec<_> = block
            .0
            .iter()
            .map(|n| Token::U32(n.as_canonical_u32()))
            .collect();
        assert_tokens(
            &block,
            &[
                &[Token::Tuple { len: 4 }],
                &u32_tokens[..],
                &[Token::TupleEnd],
            ]
            .concat(),
        );
    }

    #[rstest]
    #[case(Block::from(&[1,0,0,0]), hex!("80000001").to_vec())]
    #[case(Block::from(&[0,1,0,0]), hex!("00000000 00000001 00000000 00000000").to_vec())]
    #[case(Block::from(&[0,1,2,3]), hex!("00000000 00000001 00000002 00000003").to_vec())]
    fn serialization_with_bincode(#[case] block: Block<BabyBear>, #[case] expected: Vec<u8>) {
        let serialized_block = bincode::serde::encode_to_vec(
            &block,
            bincode::config::legacy()
                .with_fixed_int_encoding()
                .with_big_endian(),
        )
        .unwrap();
        assert_eq!(serialized_block, expected)
    }
}
