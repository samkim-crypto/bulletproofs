use core::ops::{Add, Sub, Neg};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use bincode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct GroupEncoding(pub RistrettoPoint);

impl Hash for GroupEncoding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        bincode::serialize(self).unwrap().hash(state);
    }
}

pub struct GroupIterator {
    pub curr: GroupEncoding,
    pub step: GroupEncoding,
}

impl GroupIterator {
    fn new(curr: GroupEncoding, step: GroupEncoding) -> Self {
        GroupIterator{ curr, step }
    }
}

impl Iterator for GroupIterator {
    type Item = GroupEncoding;

    fn next(&mut self) -> Option<Self::Item> {
        let r = self.curr;
        self.curr = self.curr + self.step;
        Some(r)
    }
}


impl GroupEncoding {
    pub fn encode(amount: u16) -> Self {
        GroupEncoding(Scalar::from(amount) * G)
    }

    pub fn decode(self) -> Option<u16> {
        let mut hashmap = HashMap::new();

        let id_enc = GroupEncoding(RistrettoPoint::identity());
        let gen_enc = GroupEncoding(G);

        let group_iter = GroupIterator::new(id_enc, gen_enc);
        group_iter.zip(0..std::u16::MAX).for_each(|(elem, j)| {
            hashmap.insert(elem, j);
        });

        //println!("{:?}", hashmap);

        let group_iter = GroupIterator::new(self, -GroupEncoding::encode(256));

        let mut decode = None;
        group_iter.zip(0..std::u16::MAX).for_each(|(elem, i)| {
            if hashmap.contains_key(&elem) {
                let j = hashmap[&elem];
                decode = Some((i as u16) * 256 + (j as u16));
            }
        });

        decode
    }
}

impl Add for GroupEncoding {
    type Output = GroupEncoding;

    fn add(self, other: GroupEncoding) -> GroupEncoding {
        GroupEncoding(self.0 + other.0)
    }
}

impl Sub for GroupEncoding {
    type Output = GroupEncoding;

    fn sub(self, other: GroupEncoding) -> GroupEncoding {
        GroupEncoding(self.0 - other.0)
    }
}

impl Neg for GroupEncoding {
    type Output = GroupEncoding;

    fn neg(self) -> GroupEncoding {
        GroupEncoding(-self.0)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let amount = 278;
        let M = GroupEncoding::encode(amount);

        // println!("Plain: {:?}", amount);
        // println!("Encoded: {:?}", M);

        // assert_eq!(M.0, G * Scalar::from(amount));

        // println!("{:?}", GroupEncoding::decode(M));

        assert_eq!(amount, GroupEncoding::decode(M).unwrap());
    }
}
