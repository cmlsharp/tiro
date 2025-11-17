use strobe::Strobe;
use strobe::mode;
pub use strobe::sec_param::{self, SecParam};

/// A transcript of a public-coin argument.
///
/// The prover's messages are added to the transcript using
/// [`append_message`](Transcript::append_message), and the verifier's
/// challenges can be computed using
/// [`challenge_bytes`](Transcript::challenge_bytes).
///
/// # Creating and using an Arthur transcript
///
/// To create an Arthur transcript, use [`Transcript::new()`].  This
/// function takes a domain separation label which should be unique to
/// the application.
///
/// To use the transcript with an Arthur-based proof implementation,
/// the prover's side creates a Arthur transcript with an
/// application-specific domain separation label, and passes a `&mut`
/// reference to the transcript to the proving function(s).
///
/// To verify the resulting proof, the verifier creates their own
/// Arthur transcript using the same domain separation label, then
/// passes a `&mut` reference to the verifier's transcript to the
/// verification function.
pub struct RawTranscript<S = sec_param::B128> {
    strobe: Strobe<S>,
}

impl<S> Clone for RawTranscript<S> {
    fn clone(&self) -> Self {
        RawTranscript {
            strobe: self.strobe.clone(),
        }
    }
}

pub const PROTOCOL_NAME: &[u8] = b"tiro::RawTranscript";
pub const PROTOCOL_VERSION: u32 = 1;

//const FORK_CHALLENGE_BYTES: usize = 32;

fn len_to_bytes(len: usize) -> [u8; 4] {
    u32::try_from(len)
        .expect("slice length must fit into 4 bytes")
        .to_le_bytes()
}

impl<S: SecParam> RawTranscript<S> {
    /// Initialize a new transcript with the supplied `label`, which
    /// is used as a domain separator.
    ///
    /// # Note
    ///
    /// This function should be called by a proof library's API
    /// consumer (i.e., the application using the proof library), and
    /// **not by the proof implementation**.
    pub fn new(label: &[u8]) -> RawTranscript<S> {
        let mut protocol_header = [0; PROTOCOL_NAME.len() + 4];
        let version_bytes = u32::to_le_bytes(PROTOCOL_VERSION);
        protocol_header[0..4].copy_from_slice(&version_bytes);
        protocol_header[4..][..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
        let mut transcript = RawTranscript::<S> {
            strobe: Strobe::new(&protocol_header),
        };

        transcript.append_message(b"PROTOCOL_START", label);
        transcript
    }

    /// Equivalent to [`Transcript::new`] but takes the singleton security parameter to aid type
    /// inference
    pub fn with_sec_param(_sec_param: S, label: &[u8]) -> RawTranscript<S> {
        Self::new(label)
    }

    pub fn append_message(&mut self, label: &[u8], message: &[u8]) -> &mut Self {
        let msg_len = len_to_bytes(message.len());
        self.strobe
            .mode(mode::MetaAssocData)
            //.update([Action::Message as u8])
            .update(label)
            .update(msg_len)
            .mode(mode::AssocData)
            .update(message);
        self
    }

    pub fn append_u64(&mut self, label: &[u8], x: u64) -> &mut Self {
        let bytes = u64::to_le_bytes(x);
        self.append_message(label, &bytes);
        self
    }

    pub fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) -> &mut Self {
        self.strobe
            .mode(mode::MetaAssocData)
            //.update([Action::Message as u8])
            .update(label)
            .update(len_to_bytes(dest.len()))
            .mode(mode::Prf)
            .read(dest);
        self
    }

    pub fn build_rng(self) -> TranscriptRngBuilder<S> {
        TranscriptRngBuilder {
            strobe: self.strobe,
        }
    }

    //pub fn fork<const CHALLENGE_BYTES: usize>(&mut self) -> Self {
    //    let mut fork_label = [0u8; CHALLENGE_BYTES];
    //    self.strobe
    //        .mode(mode::MetaAssocData)
    //        .update([Action::Fork as u8])
    //        .mode(mode::Prf)
    //        .read(&mut fork_label);
    //    let mut forked_transcript = self.clone();

    //    forked_transcript
    //        .strobe
    //        .mode(mode::MetaAssocData)
    //        .update([Action::Fork as u8])
    //        .update(u32::to_le_bytes(CHALLENGE_BYTES as u32))
    //        .mode(mode::AssocData)
    //        .update(fork_label);
    //    forked_transcript
    //}

    //pub fn concat<const CHALLENGE_BYTES: usize>(&mut self, mut other: Self) {
    //    let mut append_label = [0u8; CHALLENGE_BYTES];
    //    other
    //        .strobe
    //        .mode(mode::MetaAssocData)
    //        .update([Action::Join as u8])
    //        .mode(mode::Prf)
    //        .read(&mut append_label);

    //    self.strobe
    //        .mode(mode::MetaAssocData)
    //        .update([Action::Join as u8])
    //        .update(u32::to_le_bytes(FORK_CHALLENGE_BYTES as u32))
    //        .mode(mode::AssocData)
    //        .update(append_label);
    //}
}

pub struct TranscriptRngBuilder<S = sec_param::B128> {
    strobe: Strobe<S>,
}

impl<S: SecParam> TranscriptRngBuilder<S> {
    pub fn rekey_with_witness(mut self, label: &[u8], witness: &[u8]) -> Self {
        self.strobe
            .mode(mode::MetaAssocData)
            .update(label)
            .update(len_to_bytes(witness.len()))
            .mode(mode::Key)
            .update(witness);

        self
    }

    pub fn finalize(mut self, mut rng: impl rand_core::CryptoRng) -> TranscriptRng<S> {
        let random_bytes = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        };
        self.strobe
            .mode(mode::MetaAssocData)
            .update(b"rng")
            .mode(mode::Key)
            .update(random_bytes);
        TranscriptRng {
            strobe: self.strobe,
        }
    }
}

pub struct TranscriptRng<S = sec_param::B128> {
    strobe: Strobe<S>,
}

impl<S: SecParam> rand_core::RngCore for TranscriptRng<S> {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.strobe
            .mode(mode::MetaAssocData)
            .update(len_to_bytes(dest.len()))
            .mode(mode::Prf)
            .read(dest);
    }
}

impl<S: SecParam> rand_core::CryptoRng for TranscriptRng<S> {}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn works() {
        let mut trans = RawTranscript::<sec_param::B128>::new(b"hey");
        let label = b"hey!";
        println!("{:?}", label);
        trans.append_message(b"message1", b"hello");
    }
}
