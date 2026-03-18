use core::marker::PhantomData;

pub mod raw;
use raw::RawTranscript;

pub mod from_bytes;
use from_bytes::{Array, FromByteRepr};

#[cfg(feature = "derive")]
pub use tiro_derive::define_protocol;

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
pub trait Protocol {
    const NAME: &str;
    type Statement: serde::Serialize;
    type First: Interaction;
}

// A sentinel for no further interactions
pub enum ProtocolEnd {}

/// Phantom type indicating a Transcrpit is ready to recieve a prover Message
pub enum MessagePhase {}
/// Phantom type indicating a Transcript is ready to produce a challenge
pub enum ChallengePhase {}

pub enum InitPhase {}

#[must_use]
pub struct Transcript<Inter, State = InitPhase> {
    raw: RawTranscript,
    round: u32,
    _state: PhantomData<(Inter, State)>,
}

// Internal constructors for Transcript
impl<Inter, State> Transcript<Inter, State> {
    fn from_raw(raw: RawTranscript, round: u32) -> Self {
        Self {
            raw,
            round,
            _state: PhantomData,
        }
    }
}

impl<S: Protocol> Transcript<S> {
    pub fn new(label: &str, statement: &S::Statement) -> Transcript<S::First, MessagePhase> {
        let mut raw = RawTranscript::new(S::NAME.as_bytes());
        raw.append_message(
            label.as_bytes(),
            &bcs::to_bytes(&statement).expect("statement is serializable"),
        );
        Transcript::from_raw(raw, 0)
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
        self.raw.append_message(&round_bytes, &bytes);
        Ok(Transcript::from_raw(self.raw, self.round))
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
        self.raw.challenge_bytes(&round_bytes, &mut chall_buf);

        (
            Transcript::from_raw(
                self.raw,
                // this should really never actually panic
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
