#![no_std]
#![warn(clippy::all, clippy::pedantic)]
use core::ops::{Deref, DerefMut};
use sec_param::{B128, SecParam};
use zeroize::ZeroizeOnDrop;

mod keccak;
use keccak::KeccakState;

#[cfg(feature = "mac")]
#[derive(Debug, Clone, Copy)]
pub struct AuthError;

#[cfg(feature = "mac")]
impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(feature = "mac")]
impl core::error::Error for AuthError {}

bitflags::bitflags! {
    pub struct Flags: u8 {
        /// Is the data inbound
        const I = 1 << 0;
        /// Is the data sent to the application
        const A = 1 << 1;
        /// Does the operation use cipher output
        const C = 1 << 2;
        /// Is the data being sent for transport
        const T = 1 << 3;
        /// Metadata
        const M = 1 << 4;
        /// Reserved (currently unused)
        const K = 1 << 5;

    }
}

#[allow(clippy::must_use_candidate, clippy::return_self_not_must_use)]
pub mod mode {
    use super::Flags;
    use super::SecParam;
    use super::StrobeMode;
    use super::sealed;

    pub trait Mode: sealed::Sealed + Default + Eq {
        /// Returns the flags associated with this mode
        /// Ideally this would be an associated constant
        /// But const traits haven't landed yet
        fn flags() -> Flags;
    }

    macro_rules! impl_mode {
        ($name: ident, $meta_name: ident, $flags: expr, $doc:expr $(, $rest:tt)? $(,)?) => {
            impl_mode!(@inner $name, $flags, $doc, $($rest)?);
            impl_mode!(@inner $meta_name, $flags | Flags::M,
                concat!(
                    "Metadata about the [",
                    stringify!($name), "]",
                    "(crate::mode::",
                    stringify!($name),
                    ") operation"),
                $($rest)?);
        };
        (@inner $name: ident, $flags: expr, $doc:expr, $($rest:tt)?) => {
            #[derive(Clone, Copy, Eq, PartialEq, Default)]
            #[doc = $doc]
            pub struct $name;

            impl sealed::Sealed for $name {}

            impl Mode for $name {
                fn flags() -> Flags {
                    $flags
                }
            }

            $(trait_impl!($name, $rest);)?
        };

    }
    macro_rules! trait_impl {
        ($name: ident, ($f_name: ident => $method: expr)) => {
            impl<S: SecParam> StrobeMode<'_, S, $name> {
                /// Mixes data into the internal state
                pub fn $f_name(self, data: impl AsRef<[u8]>) -> Self {
                    self.parent.update(data.as_ref(), $method);
                    self
                }
            }
        };
        ($name: ident, (mut $f_name: ident => $method:expr)) => {
            impl<S: SecParam> StrobeMode<'_, S, $name> {
                /// Outpus data from the internal state
                pub fn $f_name(self, mut buffer: impl AsMut<[u8]>) -> Self {
                    self.parent.update(buffer.as_mut(), $method);
                    self
                }
            }
        };
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn absorb(st: &mut u8, dat: &u8) {
        *st ^= dat;
    }

    pub(crate) fn exchange(st: &mut u8, dat: &mut u8) {
        *dat ^= *st;
        *st ^= *dat;
    }

    impl_mode!(
        AssocData,
        MetaAssocData,
        Flags::A,
        "Mixes associated data into the internal state.",
        (update => absorb)
    );
    impl_mode!(
        Prf,
        MetaPrf,
        Flags::I | Flags::A | Flags::C,
        "Extracts pseudorandom data as a function of the internal state.",
        (mut read => |st, dat| *dat = core::mem::take(st)),
    );

    impl_mode!(
        Key,
        MetaKey,
        Flags::A | Flags::C,
        "Sets a symmetric cipher key",
        (update => |st, dat| *st = *dat),
    );

    impl_mode!(
        SendClr,
        MetaSendClr,
        Flags::A | Flags::T,
        "Sends a plaintext message",
        (update => absorb),
    );

    impl_mode!(
        RecvClr,
        MetaRecvClr,
        Flags::A | Flags::I | Flags::T,
        "Receives a plaintext message",
        (update => absorb),
    );

    impl_mode!(
        SendMac,
        MetaSendMac,
        Flags::C | Flags::T,
        "Sends MAC of the internal state",
        (mut read => |st, dat| *dat = *st),
    );

    impl_mode!(
        SendEnc,
        MetaSendEnc,
        Flags::A | Flags::C | Flags::T,
        "Sends an encrypted message",
        (mut read => |st, dat| { *st ^= *dat; *dat = *st })
    );

    impl_mode! {
        RecvEnc,
        MetaRecvEnc,
        Flags::A | Flags::C | Flags::T | Flags::I,
        "Receives an encrypted message",
        (mut read => exchange)
    }

    impl_mode!(
        RecvMac,
        MetaRecvMac,
        Flags::C | Flags::T,
        "Attempts to authenticate current state against a MAC."
    );

    #[cfg(feature = "mac")]
    mod mac {
        use super::{MetaRecvMac, Mode, RecvMac, SecParam, StrobeMode, exchange};
        use crate::Strobe;
        use zeroize::Zeroize;
        impl<'a, S: SecParam> StrobeMode<'a, S, RecvMac> {
            /// Verifies the MAC extracted from STROBE state
            ///
            /// # Errors
            /// Returns a [`strobe_hash::AuthError`] to indicate authentication failure
            pub fn verify<const N: usize>(
                self,
                mac: [u8; N],
            ) -> Result<&'a mut Strobe<S>, crate::AuthError> {
                generalized_mac(self, mac)
            }
        }

        impl<'a, S: SecParam> StrobeMode<'a, S, MetaRecvMac> {
            /// Verifies the MAC extracted from STROBE state
            ///
            /// # Errors
            /// Returns a [`strobe_hash::AuthError`] to indicate authentication failure
            pub fn verify<const N: usize>(
                self,
                mac: [u8; N],
            ) -> Result<&'a mut Strobe<S>, crate::AuthError> {
                generalized_mac(self, mac)
            }
        }

        trait GenMacRecv: Mode {}
        impl GenMacRecv for RecvMac {}
        impl GenMacRecv for MetaRecvMac {}

        fn generalized_mac<const N: usize, M: GenMacRecv, S: SecParam>(
            ctx: StrobeMode<'_, S, M>,
            mut mac: [u8; N],
        ) -> Result<&'_ mut Strobe<S>, crate::AuthError> {
            use cnti::{CtBool, CtEq};
            ctx.parent.update(&mut mac, exchange);

            let all_zero = mac
                .into_iter()
                .fold(CtBool::TRUE, |acc, b| acc & b.ct_eq(&0))
                .expose();

            mac.zeroize();

            all_zero.then_some(ctx.parent).ok_or(crate::AuthError)
        }
    }

    impl_mode! {
        Ratchet,
        MetaRatchet,
        Flags::C,
        "Ratchets the internal state forward in an irreversible way by zeroing bytes.

Takes a `usize` argument specifying the number of bytes of public state to zero. If the
size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.",
    }

    impl<S: SecParam> StrobeMode<'_, S, Ratchet> {
        pub fn ratchet(self, bytes_to_zero: usize) -> Self {
            self.parent
                .update(core::iter::repeat_n(0, bytes_to_zero), |st, dat| *st = dat);
            self
        }
    }

    impl<S: SecParam> StrobeMode<'_, S, MetaRatchet> {
        pub fn ratchet(self, bytes_to_zero: usize) -> Self {
            self.parent
                .update(core::iter::repeat_n(0, bytes_to_zero), |st, dat| *st = dat);
            self
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

pub mod sec_param {
    use super::sealed;
    #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
    pub struct B256;
    #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
    pub struct B128;

    pub trait SecParam: sealed::Sealed + Default {
        const BITS: usize;
    }

    impl sealed::Sealed for B256 {}
    impl sealed::Sealed for B128 {}

    impl SecParam for B256 {
        const BITS: usize = 256;
    }

    impl SecParam for B128 {
        const BITS: usize = 128;
    }
}

pub struct Strobe<S = B128> {
    state: KeccakState,
    pos: u8,
    pos_begin: u8,
    is_receiver: Option<bool>,
    _marker: core::marker::PhantomData<S>,
}

impl<S> Clone for Strobe<S> {
    fn clone(&self) -> Self {
        Strobe {
            state: self.state,
            pos: self.pos,
            pos_begin: self.pos_begin,
            is_receiver: self.is_receiver,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<S> ZeroizeOnDrop for Strobe<S> {}

pub struct StrobeMode<'a, S, A> {
    parent: &'a mut Strobe<S>,
    _marker: core::marker::PhantomData<A>,
}

impl<S, A> Deref for StrobeMode<'_, S, A> {
    type Target = Strobe<S>;
    fn deref(&self) -> &Self::Target {
        self.parent
    }
}

impl<S, A> DerefMut for StrobeMode<'_, S, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.parent
    }
}

// Blanket AsRef implementation suggested for types that implement Deref
// https://doc.rust-lang.org/std/convert/trait.AsRef.html
impl<'a, T, S, A> AsRef<T> for StrobeMode<'a, S, A>
where
    T: ?Sized,
    <StrobeMode<'a, S, A> as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

// Corresponding blanket AsMut implementation
impl<'a, T, S, A> AsMut<T> for StrobeMode<'a, S, A>
where
    T: ?Sized,
    <StrobeMode<'a, S, A> as Deref>::Target: AsMut<T>,
{
    fn as_mut(&mut self) -> &mut T {
        self.deref_mut().as_mut()
    }
}

impl<S: SecParam> Strobe<S> {
    #[allow(clippy::cast_possible_truncation)]
    const BYTE_RATE: u8 = {
        let rate = KeccakState::BYTE_LEN - S::BITS / 4 - 2;
        assert!(rate < 256);
        rate as u8
    };

    // i don't think there's any meaning for minor versioning on this protocol?
    // if the protocol changes at all its a breaking change inherently
    const PROTOCOL_VERSION: u32 = 1;
    // we probably won't have more than 4bn releases
    const fn protocol_header() -> [u8; 16] {
        let version_bytes = u32::to_le_bytes(Self::PROTOCOL_VERSION);
        [
            0x01,
            Self::BYTE_RATE + 2,
            0x01,
            0x00,
            0x01,
            0x60,
            version_bytes[0],
            version_bytes[1],
            version_bytes[2],
            version_bytes[3],
            b'S',
            b't',
            b'r',
            b'o',
            b'b',
            b'e',
        ]
    }

    #[must_use]
    pub fn with_sec_param(_sec_param: S, protocol_label: &[u8]) -> Self {
        Self::new(protocol_label)
    }

    #[must_use]
    pub fn new(protocol_label: &[u8]) -> Self {
        let state = {
            let mut state = KeccakState::new();
            let protocol_header = Self::protocol_header();
            state.as_mut_bytes()[..protocol_header.len()].copy_from_slice(&protocol_header);
            state.permute();
            state
        };

        let mut ret = Strobe {
            state,
            pos: 0,
            pos_begin: 0,
            is_receiver: None,
            _marker: core::marker::PhantomData,
        };
        ret.mode(mode::MetaAssocData).update(protocol_label);
        ret
    }

    pub fn mode<C: mode::Mode>(&mut self, _mode: C) -> StrobeMode<'_, S, C> {
        self.begin_op(C::flags());
        StrobeMode {
            parent: self,
            _marker: core::marker::PhantomData,
        }
    }

    fn permute(&mut self) {
        let state_bytes = self.state.as_mut_bytes();
        state_bytes[usize::from(self.pos)] ^= self.pos_begin;
        state_bytes[usize::from(self.pos) + 1] ^= 0x04;
        state_bytes[usize::from(Self::BYTE_RATE) + 1] ^= 0x80;
        self.state.permute();
        self.pos = 0;
        self.pos_begin = 0;
    }

    // TODO: at some point ould consider optimizing for performance using SIMD?
    // maybe compiler is smart enough but probably not
    fn update<I, F>(&mut self, iter: I, mut comb: F)
    where
        F: FnMut(&mut u8, I::Item),
        I: IntoIterator,
    {
        for input in iter {
            comb(&mut self.state.as_mut_bytes()[usize::from(self.pos)], input);
            self.pos += 1;
            if self.pos == Self::BYTE_RATE {
                self.permute();
            }
        }
    }

    fn begin_op(&mut self, mut flags: Flags) {
        if flags.contains(Flags::T) {
            let is_op_receiving = flags.contains(Flags::I);
            let is_receiver = self.is_receiver.unwrap_or(is_op_receiving);
            self.is_receiver = Some(is_receiver);
            flags.set(Flags::I, is_receiver != is_op_receiving);
        }

        let old_begin = self.pos_begin;
        self.pos_begin += 1;
        self.update(&[old_begin, flags.bits()], mode::absorb);
        let force_permute = flags.intersects(Flags::C | Flags::K);
        if force_permute && self.pos != 0 {
            self.permute();
        }
    }
}

#[test]
fn endiannness() {
    let mut strobe = Strobe::with_sec_param(B128, b"test");
    let mut buf = [0u8; 20];
    strobe
        .mode(mode::AssocData)
        .update(b"test")
        .mode(mode::Prf)
        .read(&mut buf);

    assert_eq!(
        &[
            114, 22, 52, 137, 49, 216, 132, 252, 102, 27, 49, 113, 86, 64, 38, 84, 73, 187, 24, 134
        ],
        &buf,
    );
}
