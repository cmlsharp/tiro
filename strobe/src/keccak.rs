use zeroize::Zeroize;

// TODO consider replacing with
// #[derive(zerocopy::IntoBytes)]
// pub(crate) struct KeccakState([u64; Self::WORD_LEN])
// this would let us have no unsafe code, but would require taking an extra dependency
#[derive(Clone, Copy)]
pub struct KeccakState([u64; Self::WORD_LEN]);

impl Zeroize for KeccakState {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Default for KeccakState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakState {
    pub(crate) const WORD_LEN: usize = 25;
    pub(crate) const BYTE_LEN: usize = Self::WORD_LEN * 8;

    #[inline]
    pub(crate) fn new() -> Self {
        Self([0; _])
    }

    #[inline]
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; Self::BYTE_LEN] {
        let ptr = (&raw mut self.0).cast();
        // #SAFETY:
        // [u64; 25] and [u8; 200] have exactly the same representation
        // and the latter has a laxer alignment than the former
        // Hence it is safe to cast a &mut [u64; 25] to a &mut [u8; 200]
        unsafe { &mut *ptr }
    }

    #[inline]
    pub(crate) fn permute(&mut self) {
        self.normalize_endianness();
        keccak::f1600(&mut self.0);
        self.normalize_endianness();
    }

    #[inline]
    /// on big-endian platforms, swap byte order before calling keccak
    /// to ensure e.g. a big-endian prover and little endian verifier agree
    /// on transcript
    fn normalize_endianness(&mut self) {
        if cfg!(target_endian = "big") {
            self.0.iter_mut().for_each(|word| *word = word.swap_bytes());
        }
    }
}
