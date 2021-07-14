use core::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::elgamal::elgamal::{ElGamalRand, ElGamalCT, ElGamalPK, ElGamalSK};
use crate::elgamal::pedersen::{PedersenGens, PedersenOpen, PedersenComm};
use crate::transcript::TranscriptProtocol;
use crate::ProofError;

use rand_core::{CryptoRng, RngCore};

#[allow(non_snake_case)]
struct InCTValidityProof {
    Y_eg_0: CompressedRistretto,
    Y_eg_1: CompressedRistretto,
    Y_p: CompressedRistretto,
    z_x: Scalar,
    z_eg: Scalar,
    z_p: Scalar,
}

#[allow(non_snake_case)]
impl InCTValidityProof {
    pub fn prove<T: RngCore + CryptoRng>(
        x: u32,
        eg_pk: ElGamalPK,
        eg_rand: ElGamalRand,
        ped_gens: PedersenGens,
        ped_open: PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut T,
    ) -> Self {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;

        let x = Scalar::from(x);
        let r_eg = eg_rand.0;
        let r_p = ped_open.0;

        let y_x = Scalar::random(rng);
        let y_eg = Scalar::random(rng);
        let y_p = Scalar::random(rng);

        let Y_eg_0 = (y_x * G + y_eg * H_eg).compress();
        let Y_eg_1 = (y_eg * G).compress();
        let Y_p = (y_x * G + y_p * H_p).compress();

        transcript.append_point(b"Y_eg_0", &Y_eg_0);
        transcript.append_point(b"Y_eg_1", &Y_eg_1);
        transcript.append_point(b"Y_p", &Y_p);

        let c = transcript.challenge_scalar(b"c");

        let z_x = c * x + y_x;
        let z_eg = c * r_eg + y_eg;
        let z_p = c * r_p + y_p;

        InCTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        }
    }

    pub fn verify(
        eg_pk: ElGamalPK,
        eg_ct: ElGamalCT,
        ped_gens: PedersenGens,
        ped_comm: PedersenComm,
        transcript: &mut Transcript,
        proof: InCTValidityProof,
    ) -> Result<(), ProofError> {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;

        let InCTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        } = proof;

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0)?;
        transcript.validate_and_append_point(b"Y_eg_1", &Y_eg_1)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w"); // can otpionally be randomized
        let ww = w * w;

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(z_x)
                .chain(iter::once(z_eg))
                .chain(iter::once(-c))
                .chain(iter::once(-Scalar::one()))
                .chain(iter::once(w * z_eg))
                .chain(iter::once(-w * c))
                .chain(iter::once(-w * Scalar::one()))
                .chain(iter::once(ww * z_x))
                .chain(iter::once(ww * z_p))
                .chain(iter::once(-ww * c))
                .chain(iter::once(-ww * Scalar::one())),
            iter::once(Some(G))
                .chain(iter::once(Some(H_eg)))
                .chain(iter::once(Some(eg_ct.C_0)))
                .chain(iter::once(Y_eg_0.decompress()))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(eg_ct.C_1)))
                .chain(iter::once(Y_eg_1.decompress()))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(H_p)))
                .chain(iter::once(Some(ped_comm.0)))
                .chain(iter::once(Y_p.decompress()))
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

#[allow(non_snake_case)]
struct OutCTValidityProof {
    Y_eg_0: CompressedRistretto,
    Y_eg_1: CompressedRistretto,
    Y_p: CompressedRistretto,
    z_sk: Scalar,
    z_x: Scalar,
    z_p: Scalar,
}
#[allow(non_snake_case)]
impl OutCTValidityProof {
    pub fn prove<T: RngCore + CryptoRng>(
        x: u64,
        eg_ct: ElGamalCT,
        eg_sk: ElGamalSK,
        ped_gens: PedersenGens,
        ped_open: PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut T,
    ) -> Self {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_p = ped_gens.H;
        let C_1 = eg_ct.C_1;

        let sk = eg_sk.0;
        let x = Scalar::from(x);
        let r_p = ped_open.0;

        let y_sk = Scalar::random(rng);
        let y_x = Scalar::random(rng);
        let y_p = Scalar::random(rng);

        let Y_eg_0 = (y_x * G + y_sk * C_1).compress();
        let Y_eg_1 = (y_sk * G).compress();
        let Y_p = (y_x * G + y_p * H_p).compress();

        transcript.append_point(b"Y_eg_0", &Y_eg_0);
        transcript.append_point(b"Y_eg_1", &Y_eg_1);
        transcript.append_point(b"Y_p", &Y_p);

        let c = transcript.challenge_scalar(b"c");

        let z_sk = c * sk + y_sk;
        let z_x = c * x + y_x;
        let z_p = c * r_p + y_p;

        OutCTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_sk,
            z_x,
            z_p,
        }
    }

    pub fn verify(
        eg_pk: ElGamalPK,
        eg_ct: ElGamalCT,
        ped_gens: PedersenGens,
        ped_comm: PedersenComm,
        transcript: &mut Transcript,
        proof: OutCTValidityProof,
    ) -> Result<(), ProofError> {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;
        let C_0 = eg_ct.C_0;
        let C_1 = eg_ct.C_1;

        let OutCTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_sk,
            z_x,
            z_p,
        } = proof;

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0)?;
        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_1)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w");
        let ww = w * w;

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(z_x)
                .chain(iter::once(z_sk))
                .chain(iter::once(-c))
                .chain(iter::once(-Scalar::one()))
                .chain(iter::once(w * z_sk))
                .chain(iter::once(-w * c))
                .chain(iter::once(-w * Scalar::one()))
                .chain(iter::once(ww * z_x))
                .chain(iter::once(ww * z_p))
                .chain(iter::once(-ww * c))
                .chain(iter::once(-ww * Scalar::one())),
            iter::once(Some(G))
                .chain(iter::once(Some(C_1)))
                .chain(iter::once(Some(C_0)))
                .chain(iter::once(Y_eg_1.decompress()))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(H_eg)))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(H_p)))
                .chain(iter::once(Some(ped_comm.0)))
                .chain(iter::once(Y_p.decompress()))
        )
        .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

struct NetZeroProof {

}

impl NetZeroProof {
    pub fn prove<T: RngCore + CryptoRng>(
        x: u64,
        eg_pk: ElGamalPK,
        eg_ct: ElGamalCT,
        eg_rand: ElGamalRand,
        ped_gens: PedersenGens,
        ped_comm: PedersenComm,
        ped_open: PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut T,
    ) -> NetZeroProof {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;

        let x = Scalar::from(x);
        let r_eg = eg_rand.0;
        let r_p = ped_open.0;

        NetZeroProof { }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {

    }

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
