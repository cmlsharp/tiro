use core::marker::PhantomData;

use hybrid_array::Array;

pub mod raw;
use raw::RawTranscript;

pub mod from_bytes;
use from_bytes::FromByteRepr;

#[cfg(feature = "derive")]
pub use tiro_derive::FromByteRepr;

pub trait RoundSpec {
    const LABEL: &str;
    type Input: serde::Serialize;
    type Challenge: FromByteRepr;
}

pub enum InputPhase {}
pub enum ChallengePhase {}
pub enum ExtendPhase {}

#[must_use]
pub struct Transcript<Spec, State> {
    transcript: RawTranscript,
    _state: PhantomData<(State, Spec)>,
}

#[derive(Debug, Clone)]
pub struct SerializationError {
    inner: bcs::Error,
}

impl core::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl core::error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl<Spec, State> Transcript<Spec, State> {
    fn from_raw(transcript: RawTranscript) -> Self {
        Self {
            transcript,
            _state: PhantomData,
        }
    }

    fn new_type_state<Spec2, State2>(self) -> Transcript<Spec2, State2> {
        Transcript::from_raw(self.transcript)
    }
}

impl<S: RoundSpec> Transcript<S, InputPhase> {
    pub fn new(label: &[u8], statement: impl serde::Serialize) -> Self {
        let mut raw = RawTranscript::new(label);
        raw.append_message(
            b"stmt",
            &bcs::to_bytes(&statement).expect("statement is serializable"),
        );
        Self::from_raw(raw)
    }

    pub fn try_input(
        mut self,
        input: &S::Input,
    ) -> Result<Transcript<S, ChallengePhase>, SerializationError> {
        let bytes = bcs::to_bytes(input).map_err(|e| SerializationError { inner: e })?;
        self.transcript.append_message(S::LABEL.as_bytes(), &bytes);
        Ok(self.new_type_state())
    }

    pub fn input(self, input: &S::Input) -> Transcript<S, ChallengePhase> {
        self.try_input(input)
            .expect("serialization of input is successful")
    }
}

impl<S: RoundSpec> Transcript<S, ChallengePhase> {
    pub fn challenge(mut self) -> (Transcript<S, ExtendPhase>, S::Challenge) {
        let mut chall_buf = Array::default();
        self.transcript
            .challenge_bytes(S::LABEL.as_bytes(), &mut chall_buf);

        (self.new_type_state(), FromByteRepr::from_bytes(&chall_buf))
    }
}

impl<D: RoundSpec> Transcript<ExtendPhase, D> {
    pub fn extend<D2: RoundSpec>(self) -> Transcript<InputPhase, D2> {
        self.new_type_state()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::str::FromStr;
    use hybrid_array::typenum;
    use num_bigint::{BigInt, RandBigInt, Sign};
    use num_traits::Signed;
    use serde::Serialize;
    #[test]
    fn schnorr() -> Result<(), SerializationError> {
        #[derive(Serialize)]
        struct SchnorrStatement {
            modulus: BigInt,
            base: BigInt,
            target: BigInt,
        }

        type SchnorrMessage = BigInt;

        type SchnorrChallenge = [u8; 16];

        struct Schnorr;

        impl RoundSpec for Schnorr {
            const LABEL: &str = "Schnorr1";
            type Input = SchnorrMessage;
            type Challenge = SchnorrChallenge;
        }

        let target = BigInt::from(8675309u32);
        let base = BigInt::from(43u32);
        let modulus = &BigInt::from(2u32).pow(127) - BigInt::from(1u32);
        let mut rng = rand::thread_rng();
        let r = rng.gen_bigint(128).abs();
        let log = BigInt::from_str("18777797083714995725967614997933308615").unwrap();

        let message = base.modpow(&r, &modulus);

        let statement = SchnorrStatement {
            target,
            base,
            modulus,
        };

        let transcript = Transcript::<Schnorr, _>::new(b"my_protocol", statement);

        let (_, challenge) = transcript.input(&message).challenge();

        let challenge_int = BigInt::from_bytes_le(Sign::Plus, &challenge);
        let _z = (challenge_int * log) + r;
        Ok(())
    }

    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    // Note this is not necessary for this version of decree, it just lets you capture the same
    // interface old decree had with incremental initialization, but in a type-safe way;
    #[test]
    fn test_girault() {
        #[derive(Serialize)]
        struct GiraultStatement {
            base: BigUint,
            modulus: BigUint,
            target: BigUint,
        }

        #[derive(Serialize)]
        struct GiraultMessage {
            commit: BigUint,
        }

        #[derive(Debug, PartialEq)]
        struct GiraultChallenge(BigUint);

        impl FromByteRepr for GiraultChallenge {
            type Size = typenum::U128;
            fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
                GiraultChallenge(BigUint::from_bytes_le(bytes))
            }
        }

        struct Girault;

        impl RoundSpec for Girault {
            const LABEL: &str = "Girault";
            type Input = GiraultMessage;
            type Challenge = GiraultChallenge;
        }

        fn prove_girault(
            x: BigUint,
            stmt: &GiraultStatement,
        ) -> (GiraultMessage, GiraultChallenge, BigUint) {
            let r = rand::thread_rng().gen_biguint(1024);
            let commit = stmt.base.modpow(&r, &stmt.modulus);
            let message = GiraultMessage { commit };
            let (_, chall) = Transcript::<Girault, _>::new(b"girault", stmt)
                .input(&message)
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
            assert!(!msg.commit.is_one() && !msg.commit.is_zero());
            assert!(!stmt.target.is_one() && !stmt.target.is_zero());
            assert!(!stmt.base.is_one() && !stmt.base.is_zero());
            assert!(!z.is_one() && !z.is_zero());
            let transcript_verify = Transcript::<Girault, _>::new(b"girault", &stmt);
            let (_, verifier_challenge) = transcript_verify.input(&msg).challenge();

            assert_eq!(verifier_challenge, challenge);
            let check = (stmt.base.modpow(&z, &stmt.modulus)
                * stmt.target.modpow(&challenge.0, &stmt.modulus))
                % stmt.modulus;
            assert_eq!(check, msg.commit);
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
