use num_bigint::RandBigInt;
use num_traits::{One, Zero};
use serde::Serialize;

use tiro::{
    Transcript,
    from_bytes::{Array, FromByteRepr, typenum},
};

use num_bigint::BigUint;

tiro::define_protocol! {
    Girault,

    statement {
        #[derive(Serialize, Clone, Debug)]
        struct GiraultStatement {
            base: BigUint,
            modulus: BigUint,
            target: BigUint,
        }
    }

    interaction Round1 {
        message {
            #[derive(Serialize)]
            struct GiraultCommit(BigUint);
        }

        challenge {
            #[derive(Debug, PartialEq)]
            struct GiraultChallenge(BigUint);
        }

    }
}

// In reality you'd probably already have a Field elem type for your field
// with a fixed size and you could proably derive FromByteRepr for it,
// but for this toy example we'll use BigInt

impl FromByteRepr for GiraultChallenge {
    type Size = typenum::U128;
    fn from_bytes(bytes: &Array<u8, Self::Size>) -> Self {
        GiraultChallenge(BigUint::from_bytes_le(bytes))
    }
}

fn prove_girault(
    x: BigUint,
    stmt: &GiraultStatement,
) -> (GiraultCommit, GiraultChallenge, BigUint) {
    let r = rand::thread_rng().gen_biguint(1024);
    let commit = stmt.base.modpow(&r, &stmt.modulus);
    let message = GiraultCommit(commit);
    let (_, chall) = Transcript::<Girault>::new("girault", stmt)
        .message(&message)
        .challenge();
    let z = r + (x * &chall.0);
    (message, chall, z)
}

fn verify_girault(
    stmt: GiraultStatement,
    commit: GiraultCommit,
    challenge: GiraultChallenge,
    z: BigUint,
) {
    assert!(!commit.0.is_one() && !commit.0.is_zero());
    assert!(!stmt.target.is_one() && !stmt.target.is_zero());
    assert!(!stmt.base.is_one() && !stmt.base.is_zero());
    assert!(!z.is_one() && !z.is_zero());
    let transcript_verify = Transcript::<Girault>::new("girault", &stmt);
    let (_, verifier_challenge) = transcript_verify.message(&commit).challenge();

    assert_eq!(verifier_challenge, challenge);
    let check = (stmt.base.modpow(&z, &stmt.modulus)
        * stmt.target.modpow(&challenge.0, &stmt.modulus))
        % stmt.modulus;
    assert_eq!(check, commit.0);
}

#[test]
fn test_girault() {
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
