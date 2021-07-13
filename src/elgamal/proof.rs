use core::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::elgamal::elgamal::ElGamalRand;
use crate::elgamal::elgamal::ElGamalCT;
use crate::elgamal::elgamal::ElGamalPK;
use crate::elgamal::pedersen::PedersenGens;
use crate::elgamal::pedersen::PedersenOpen;
use crate::elgamal::pedersen::PedersenComm;
use crate::transcript::TranscriptProtocol;
use crate::ProofError;

use rand_core::{CryptoRng, RngCore};

#[allow(non_snake_case)]
struct CTValidityProof {
    Y_eg_0: CompressedRistretto,
    Y_eg_1: CompressedRistretto,
    Y_p: CompressedRistretto,
    z_x: Scalar,
    z_eg: Scalar,
    z_p: Scalar,
}

#[allow(non_snake_case)]
impl CTValidityProof {
    fn prove<T: Into<Scalar>, U: RngCore + CryptoRng>(
        x: T,
        eg_pk: ElGamalPK,
        eg_ct: ElGamalCT,
        eg_rand: ElGamalRand,
        ped_gens: PedersenGens,
        ped_comm: PedersenComm,
        ped_open: PedersenOpen,
        transcript: &mut Transcript,
        rng: &mut U,
    ) -> Self {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;

        let x = x.into();
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

        CTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        }
    }

    fn verify(
        eg_pk: ElGamalPK,
        eg_ct: ElGamalCT,
        ped_gens: PedersenGens,
        ped_comm: PedersenComm,
        transcript: &mut Transcript,
        proof: CTValidityProof,
    ) -> Result<(), ProofError> {
        transcript.ct_validity_domain_sep();

        let G = ped_gens.G;
        let H_eg = eg_pk.0;
        let H_p = ped_gens.H;

        let CTValidityProof {
            Y_eg_0,
            Y_eg_1,
            Y_p,
            z_x,
            z_eg,
            z_p,
        } = proof;

        transcript.validate_and_append_point(b"Y_eg_0", &Y_eg_0)?;
        transcript.validate_and_append_point(b"Y_eg_1", &Y_eg_1)?;
        transcript.validate_and_append_point(b"Y_p", &Y_p);

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.clone().challenge_scalar(b"w"); // can otpionally be randomized

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(z_x)
                .chain(iter::once(z_eg))
                .chain(iter::once(-c))
                .chain(iter::once(-Scalar::one()))
                .chain(iter::once(w * z_eg))
                .chain(iter::once(-w * c))
                .chain(iter::once(-Scalar::one()))
                .chain(iter::once(z_x))
                .chain(iter::once(z_p))
                .chain(iter::once(-c))
                .chain(iter::once(-Scalar::one())),
            iter::once(Some(G))
                .chain(iter::once(Some(H_eg)))
                .chain(iter::once(Some(eg_ct.c0)))
                .chain(iter::once(Y_eg_0.decompress()))
                .chain(iter::once(Some(G)))
                .chain(iter::once(Some(eg_ct.c1)))
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

struct NetZeroProof {

}
