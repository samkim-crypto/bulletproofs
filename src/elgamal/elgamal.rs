use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use rand::thread_rng;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use serde::{Deserialize, Serialize};

use crate::elgamal::encode::GroupEncoding;

pub struct ElGamal;
impl ElGamal {
    pub fn keygen() -> (ElGamalPK, ElGamalSK) {
        let s = Scalar::random(&mut thread_rng());
        let H = s * G;

        (ElGamalPK(H), ElGamalSK(s))
    }

    pub fn encrypt(pk: ElGamalPK, msg: GroupEncoding) -> (ElGamalCT, ElGamalRand) {
        let ElGamalPK(H) = pk;
        let GroupEncoding(M) = msg;

        let r = Scalar::random(&mut thread_rng());

        let ct = ElGamalCT {
            c0: M + r * H,
            c1: r * G,
        };

        let rand = ElGamalRand(r);

        (ct, rand)
    }

    pub fn decrypt(sk: ElGamalSK, ct: ElGamalCT) -> GroupEncoding {
        let ElGamalSK(s) = sk;
        let ElGamalCT { c0, c1 } = ct;

        GroupEncoding(c0 - s * c1)
    }
}

impl GroupEncoding {
    pub fn encrypt(self, pk: ElGamalPK) -> (ElGamalCT, ElGamalRand) {
        ElGamal::encrypt(pk, self)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalPK(pub RistrettoPoint);
impl ElGamalPK {
    pub fn encrypt(self, msg: GroupEncoding) -> (ElGamalCT, ElGamalRand) {
        ElGamal::encrypt(self, msg)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalSK(pub Scalar);
impl ElGamalSK {
    pub fn decrypt(self, ct: ElGamalCT) -> GroupEncoding {
        ElGamal::decrypt(self, ct)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalCT {
    pub c0: RistrettoPoint,
    pub c1: RistrettoPoint,
}
impl ElGamalCT {
    pub fn decrypt(self, sk: ElGamalSK) -> GroupEncoding {
        ElGamal::decrypt(sk, self)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalRand(pub Scalar);


#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn encrypt() {
    //     let (pk, sk) = ElGamal::keygen();
    //     let msg = GroupEncoding::encode(57);
    //     let ct = ElGamal::encrypt(pk, msg);

    //     // println!("pk: {:?}", pk);
    //     // println!("sk: {:?}", sk);
    //     // println!("ct: {:?}", ct);

    //     assert_eq!(ElGamal::decrypt(sk, ct), msg);
    // }
}
