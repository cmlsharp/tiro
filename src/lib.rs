use core::marker::PhantomData;

use hybrid_array::Array;

pub mod raw;
use raw::RawTranscript;

pub mod from_bytes;
use from_bytes::FromByteRepr;

#[cfg(feature = "derive")]
pub use tiro_derive::FromByteRepr;

// Represents a Prover-Verifier interaction
pub trait Interaction {
    type Message: serde::Serialize;
    type Challenge: FromByteRepr;
    // Some protocols have multiple interactions
    // 'Next' can either be another Interaction or ProtocolEnd
    type Next;
}

// Implemented for the first interaction
// Gives the protocol a name and a statement type
pub trait ProtocolStart: Interaction {
    const NAME: &str;
    type Statement: serde::Serialize;
}

// A sentinel for no further interactions
pub enum ProtocolEnd {}

/// Phantom type indicating a Transcrpit is ready to recieve a prover Message
pub enum MessagePhase {}
/// Phantom type indicating a Transcript is ready to produce a challenge
pub enum ChallengePhase {}

#[must_use]
pub struct Transcript<Inter, State> {
    transcript: RawTranscript,
    round: u32,
    _state: PhantomData<(Inter, State)>,
}

// Internal constructors for Transcript
impl<Inter, State> Transcript<Inter, State> {
    fn from_raw(transcript: RawTranscript, round: u32) -> Self {
        Self {
            transcript,
            round,
            _state: PhantomData,
        }
    }

    fn new_type_state<Inter2, State2>(self) -> Transcript<Inter2, State2> {
        Transcript::from_raw(self.transcript, self.round)
    }
}

impl<S: ProtocolStart> Transcript<S, MessagePhase> {
    pub fn new(label: &str, statement: &S::Statement) -> Self {
        let mut raw = RawTranscript::new(S::NAME.as_bytes());
        raw.append_message(
            label.as_bytes(),
            &bcs::to_bytes(&statement).expect("statement is serializable"),
        );
        Self::from_raw(raw, 0)
    }
}

impl<S: Interaction> Transcript<S, MessagePhase> {
    // I'm not sure serialization failure should really be a programmer-recoverable error
    // but just in case...
    pub fn try_message(
        mut self,
        input: &S::Message,
    ) -> Result<Transcript<S, ChallengePhase>, SerializationError> {
        let bytes = bcs::to_bytes(input).map_err(SerializationError)?;
        // domain separation between messages and challenges is actually already handled by
        // RawTranscript. But we need to supply some label, and more separation can't hurt
        let round_bytes = (self.round * 2).to_le_bytes();
        self.transcript.append_message(&round_bytes, &bytes);
        Ok(self.new_type_state())
    }

    pub fn message(self, input: &S::Message) -> Transcript<S, ChallengePhase> {
        self.try_message(input)
            .expect("input serializes successfully")
    }
}

impl<S: Interaction> Transcript<S, ChallengePhase> {
    pub fn challenge(mut self) -> (Transcript<S::Next, MessagePhase>, S::Challenge) {
        let mut chall_buf = Array::default();
        let round_bytes = (self.round * 2 + 1).to_le_bytes();
        self.transcript
            .challenge_bytes(&round_bytes, &mut chall_buf);

        (
            Transcript::from_raw(
                self.transcript,
                // this should really never happen
                // this would require a protocol with 2**32 rounds
                self.round.checked_add(1).expect("num rounds < 2**32"),
            ),
            FromByteRepr::from_bytes(&chall_buf),
        )
    }
}

#[derive(Debug, Clone)]
// From<bcs::Error> intentionally not implemented because the point of this type is to keep
// bcs::Error out of this crate's public interface
pub struct SerializationError(bcs::Error);

impl core::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hybrid_array::typenum;
    use num_bigint::RandBigInt;
    use serde::Serialize;

    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    // Note this is not necessary for this version of decree, it just lets you capture the same
    // interface old decree had with incremental initialization, but in a type-safe way;
    #[test]
    fn test_girault() {
        struct Girault;

        #[derive(Serialize)]
        struct GiraultStatement {
            base: BigUint,
            modulus: BigUint,
            target: BigUint,
        }

        #[derive(Serialize)]
        struct GiraultMessage(BigUint);

        #[derive(Debug, PartialEq)]
        // In reality you'd probably already have a Field elem type for your field
        struct GiraultChallenge(BigUint);

        impl FromByteRepr for GiraultChallenge {
            type Size = typenum::U128;
            fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
                GiraultChallenge(BigUint::from_bytes_le(bytes))
            }
        }

        impl ProtocolStart for Girault {
            const NAME: &str = "Girault";
            type Statement = GiraultStatement;
        }

        impl Interaction for Girault {
            type Message = GiraultMessage;
            type Challenge = GiraultChallenge;
            type Next = ProtocolEnd;
        }

        fn prove_girault(
            x: BigUint,
            stmt: &GiraultStatement,
        ) -> (GiraultMessage, GiraultChallenge, BigUint) {
            let r = rand::thread_rng().gen_biguint(1024);
            let commit = stmt.base.modpow(&r, &stmt.modulus);
            let message = GiraultMessage(commit);
            let (_, chall) = Transcript::<Girault, _>::new("girault", stmt)
                .message(&message)
                .challenge();
            let z = r + (x * &chall.0);
            (message, chall, z)
        }

        fn verify_girault(
            stmt: GiraultStatement,
            msg: GiraultMessage,
            challenge: GiraultChallenge,
            z: BigUint,
        ) {
            assert!(!msg.0.is_one() && !msg.0.is_zero());
            assert!(!stmt.target.is_one() && !stmt.target.is_zero());
            assert!(!stmt.base.is_one() && !stmt.base.is_zero());
            assert!(!z.is_one() && !z.is_zero());
            let transcript_verify = Transcript::<Girault, _>::new("girault", &stmt);
            let (_, verifier_challenge) = transcript_verify.message(&msg).challenge();

            assert_eq!(verifier_challenge, challenge);
            let check = (stmt.base.modpow(&z, &stmt.modulus)
                * stmt.target.modpow(&challenge.0, &stmt.modulus))
                % stmt.modulus;
            assert_eq!(check, msg.0);
        }

        // x is our secret logarithm
        let x = BigUint::from(8675309u32);

        // p = NextPrime(SHA3-512('DECREE'))
        let p = BigUint::parse_bytes(
            b"e955c307804136f22408b416ebc081ae\
              c8d940e1ebd790cbe128485b15a8064d\
              5015e2b4c0058d403670a8cfa00fe1ad\
              866312656e740e58b566fa4eddde2883",
            16,
        )
        .unwrap();

        // q = NextPrime(SHA3-512('INSCRIBE'))
        let q = BigUint::parse_bytes(
            b"d608e1552a96613570afb9e7291b2916\
              2ad18868e2f7aedeba2b321d13ab2b79\
              99a1e449e433c5947af5194471e84ce0\
              d34b30b761004c8efdad598771b37e13",
            16,
        )
        .unwrap();

        let base = BigUint::from(2u32);
        let modulus = p * q;
        // We need `g^(-1)` to compute `g^(-x)`. Since `g` is 2, we can compute this easily.
        let base_inv = (&modulus + &BigUint::one()) / &base;
        let target = base_inv.modpow(&x, &modulus);

        let stmt = GiraultStatement {
            base,
            modulus,
            target,
        };

        let (m, c, z) = prove_girault(x, &stmt);
        verify_girault(stmt, m, c, z);
    }
}
