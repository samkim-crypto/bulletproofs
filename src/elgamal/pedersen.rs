use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT};
use rand::thread_rng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use sha3::Sha3_512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenComm(pub CompressedRistretto);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenOpen(pub Scalar);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenPair {
    pub comm: PedersenComm,
    pub open: PedersenOpen,
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenGens {
    pub G: RistrettoPoint,
    pub H: RistrettoPoint,
}

impl Default for PedersenGens {
    fn default() -> PedersenGens {
        PedersenGens {
            G: RISTRETTO_BASEPOINT_POINT,
            H: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }
}

pub struct Pedersen;
impl Pedersen {
    #[allow(non_snake_case)]
    pub fn commit(amount: u64) -> PedersenPair {
        let secret_scalar = Scalar::random(&mut thread_rng());

        let PedersenGens { G, H } = PedersenGens::default();

        let comm = PedersenComm((Scalar::from(amount) * G + secret_scalar * H).compress());
        let open = PedersenOpen(secret_scalar);

        PedersenPair{ comm, open }
    }

    #[allow(non_snake_case)]
    pub fn verify(ct: PedersenComm, open: PedersenOpen, amount: u64) -> bool {
        let PedersenComm(ct) = ct;
        let PedersenOpen(open) = open;

        let PedersenGens { G, H } = PedersenGens::default();

        ct == (Scalar::from(amount) * G + open * H).compress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn commit_verify() {
    //     let (ct, open) = Pedersen::commit(75);

    //     // println!("{:?}", ct);
    //     // println!("{:?}", open);

    //     assert!(Pedersen::verify(ct, open, 75));
    // }
}
