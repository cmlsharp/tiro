use core::ops::Mul;
pub use hybrid_array::typenum;
use hybrid_array::{Array, ArrayN, ArraySize};

#[cfg(feature = "derive")]
use tiro_derive::impl_tuple;

// TODO: once const_generics improves, replace Size with a const generic
pub trait FromByteRepr {
    type Size: ArraySize;
    fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self;
}

impl<T, N> FromByteRepr for Array<T, N>
where
    T: FromByteRepr,
    N: ArraySize + Mul<T::Size, Output: ArraySize>,
{
    type Size = typenum::Prod<N, T::Size>;

    #[inline]
    fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
        // # SAFETY:
        // Array<u8, Self::Size> `bytes` is guaranteed to be repr(transparent) for an array &[u8; N::USIZE * T::Size::USIZE];
        // it would be safe to transmute this to &[[u8; T::Size::USIZE]; N::USIZE] as these have
        // the same representation
        // again, applying repr(transparent) this has the same representation as &Array<Array<u8,
        // T::Size>, N>
        debug_assert!(
            bytes.len() == <N as typenum::Unsigned>::USIZE * <T::Size as typenum::Unsigned>::USIZE
        );
        let chunk_ptr = (&raw const *bytes).cast::<Array<Array<u8, T::Size>, N>>();
        let chunks = unsafe { &*chunk_ptr };
        Array::from_fn(|i| T::from_bytes(&chunks[i]))
    }
}

impl<T, const N: usize> FromByteRepr for [T; N]
where
    T: FromByteRepr,
    [T; N]: hybrid_array::AssocArraySize<
            Size: core::ops::Mul<T::Size, Output: ArraySize> + ArraySize<ArrayType<T> = [T; N]>,
        >,
{
    type Size = typenum::Prod<<[T; N] as hybrid_array::AssocArraySize>::Size, T::Size>;

    #[inline]
    fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
        ArrayN::<T, N>::from_bytes(bytes).0
    }
}
macro_rules! impl_int {
    ($($int: ty),+) => {
        $(
        impl FromByteRepr for $int {
            type Size = typenum::U<{ (<$int>::BITS / 8) as usize }>;
            fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
                <$int>::from_le_bytes(bytes.0)
            }
        }
        )+
    };
}

impl_int!(
    i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize
);

#[cfg(feature = "derive")]
impl_tuple!(0..=16);
