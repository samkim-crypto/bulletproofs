use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::elgamal::elgamal::ElGamalRand;
use crate::elgamal::elgamal::ElGamalCT;
use crate::elgamal::elgamal::ElGamalPK;
use crate::elgamal::pedersen::PedersenOpen;
use crate::elgamal::pedersen::PedersenComm;
use crate::transcript::TranscriptProtocol;
use crate::ProofError;

use rand_core::{CryptoRng, RngCore};

#[allow(non_snake_case)]
struct CTValidityProof {
    R_0: [CompressedRistretto; 3],
    R_1: [CompressedRistretto; 3],
    R_2: [CompressedRistretto; 3],
    z_0: [Scalar; 3],
    z_1: Scalar,
    z_2: Scalar,
}

#[allow(non_snake_case)]
impl CTValidityProof {
    fn prove<T: RngCore + CryptoRng>(
        x_0: u32,
        x_1: u32,
        eg_rands: [ElGamalRand; 3],
        ped_opens: [PedersenOpen; 3],
        transcript: &mut Transcript,
        rng: &mut T,
    ) -> Self {
        let mut R_0 = [CompressedRistretto::default(); 3];
        let mut R_1 = [CompressedRistretto::default(); 3];
        let mut R_2 = [CompressedRistretto::default(); 3];
        let mut z_0 = [Scalar::default(); 3];
        let mut z_1 = Scalar::zero();
        let mut z_2 = Scalar::zero();

        let mut r_0 = [Scalar::default(); 3];
        let mut r_1 = [Scalar::default(); 3];
        let mut r_2 = [Scalar::default(); 3];

        let x_2 = (x_0 as u64) + (x_1 as u64) << 32;
        let x = [Scalar::from(x_0), Scalar::from(x_1), Scalar::from(x_2)];

        transcript.ct_validity_domain_sep();

        for i in 0..3 {
            r_0[i] = Scalar::random(rng);
            r_1[i] = Scalar::random(rng);
            r_2[i] = Scalar::random(rng);

            R_0[i] = (r_0[i] * G).compress();
            R_1[i] = (r_1[i] * G).compress();
            R_2[i] = (r_2[i] * G).compress();

            transcript.append_point(b"R_0", &R_0[i]);
            transcript.append_point(b"R_1", &R_1[i]);
            transcript.append_point(b"R_2", &R_2[i]);
        }

        let c = transcript.challenge_scalar(b"c");
        let y = transcript.challenge_scalar(b"y");

        let mut exp_y = Scalar::one();
        for i in 0..3 {
            let r_eg = eg_rands[i].0;
            let r_p = ped_opens[i].0;
            let x = x[i];

            z_0[i] = c * r_eg + r_0[i];
            z_1 += (c * x + r_1[i]) * exp_y;
            z_2 += (c * r_p + r_2[i]) * exp_y;

            exp_y *= y;
        }

        CTValidityProof {
            R_0,
            R_1,
            R_2,
            z_0,
            z_1,
            z_2,
        }
    }

    fn verify(
        eg_pks: [ElGamalPK; 3],
        eg_cts: [ElGamalCT; 3],
        ped_comms: [PedersenComm; 3],
        transcript: &mut Transcript,
        proof: CTValidityProof,
    ) -> Result<(), ProofError> {
        let CTValidityProof {
            R_0,
            R_1,
            R_2,
            z_0,
            z_1,
            z_2,
        } = proof;

        transcript.ct_validity_domain_sep();

        for i in 0..3 {
            transcript.validate_and_append_point(b"R_0", &R_0[i]);
            transcript.validate_and_append_point(b"R_1", &R_1[i]);
            transcript.validate_and_append_point(b"R_2", &R_2[i]);
        }

        let c = transcript.challenge_scalar(b"c");
        let y = transcript.challenge_scalar(b"y");

        let mut exp_y = Scalar::one();
        for i in 0..3 {
            let z_0 = z_0[i];
            let z_1 = z_1[i];
            let z_2 = z_2[i];

            let H = eg_pks[i].0;
            let ElGamalCT { c0: ct_0, c1: ct_1 } = eg_cts[i];

            let R_0 = R_0[i].decompress();

        }

        Ok(())
    }
}

struct NetZeroProof {

}
