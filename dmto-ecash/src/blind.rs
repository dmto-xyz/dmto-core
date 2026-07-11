use rand::RngCore;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// (De)serialize a [`Scalar`] as its 32-byte big-endian encoding, since
/// `secp256k1::Scalar` does not implement `serde` itself.
mod scalar_serde {
    use secp256k1::Scalar;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(scalar: &Scalar, s: S) -> std::result::Result<S::Ok, S::Error> {
        scalar.to_be_bytes().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Scalar, D::Error> {
        let bytes = <[u8; 32]>::deserialize(d)?;
        Scalar::from_be_bytes(bytes).map_err(|_| serde::de::Error::custom("scalar out of range"))
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub blinded_point: PublicKey,
    #[serde(with = "scalar_serde")]
    pub blind_factor: Scalar,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DLEQ {
    #[serde(with = "scalar_serde")]
    pub e: Scalar,
    #[serde(with = "scalar_serde")]
    pub s: Scalar,
}

fn random_scalar() -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(s) = Scalar::from_be_bytes(bytes)
            && s != Scalar::ZERO
        {
            return s;
        }
    }
}

fn scalar_to_secret(s: &Scalar) -> Result<SecretKey> {
    SecretKey::from_slice(&s.to_be_bytes()).map_err(Error::from)
}

pub fn blind_message(y: &PublicKey) -> Result<BlindedMessage> {
    let secp = Secp256k1::new();
    let r = random_scalar();

    let r_g = PublicKey::from_secret_key(&secp, &scalar_to_secret(&r)?);
    let blinded_point = y.combine(&r_g)?;

    Ok(BlindedMessage {
        blinded_point,
        blind_factor: r,
    })
}

pub fn blind_sign(privkey: &SecretKey, blinded_point: &PublicKey) -> Result<(PublicKey, DLEQ)> {
    let secp = Secp256k1::new();
    let a = Scalar::from_be_bytes(privkey.secret_bytes()).map_err(|_| Error::InvalidScalar)?;

    let c_prime = blinded_point.mul_tweak(&secp, &a)?;

    // Generate DLEQ proof: prove log_G(A) == log_{B'}(C')
    let r = random_scalar(); // nonce
    let r_g = PublicKey::from_secret_key(&secp, &scalar_to_secret(&r)?); // R1 = r*G
    let r_b = blinded_point.mul_tweak(&secp, &r)?; // R2 = r*B'

    let a_pub = PublicKey::from_secret_key(&secp, privkey); // A = a*G

    // Challenge e = hash(R1 || R2 || A || C')
    let mut hasher = Sha256::new();
    hasher.update(r_g.serialize());
    hasher.update(r_b.serialize());
    hasher.update(a_pub.serialize());
    hasher.update(c_prime.serialize());
    let hash = hasher.finalize();

    let e = Scalar::from_be_bytes(hash.into()).map_err(|_| Error::InvalidScalar)?;
    let e_sk = scalar_to_secret(&e)?;

    // s = r + e*a
    let s1 = e_sk.mul_tweak(&a)?;
    let r_sk = scalar_to_secret(&r)?;
    let s_sk = r_sk
        .add_tweak(&Scalar::from_be_bytes(s1.secret_bytes()).map_err(|_| Error::InvalidScalar)?)?;
    let s = Scalar::from_be_bytes(s_sk.secret_bytes()).map_err(|_| Error::InvalidScalar)?;

    Ok((c_prime, DLEQ { e, s }))
}

pub fn unblind_signature(
    blind_sig: &PublicKey,
    blind_factor: &Scalar,
    mint_pubkey: &PublicKey,
) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let r_k = mint_pubkey.mul_tweak(&secp, blind_factor)?;
    blind_sig.combine(&r_k.negate(&secp)).map_err(Error::from)
}

/// Verify a DLEQ proof. Returns `false` on any invalid or malformed input rather
/// than panicking, since the proof may come from an untrusted source.
pub fn verify_dleq(
    b_prime: &PublicKey,
    c_prime: &PublicKey,
    a_pub: &PublicKey,
    proof: &DLEQ,
) -> bool {
    verify_dleq_inner(b_prime, c_prime, a_pub, proof).unwrap_or(false)
}

fn verify_dleq_inner(
    b_prime: &PublicKey,
    c_prime: &PublicKey,
    a_pub: &PublicKey,
    proof: &DLEQ,
) -> Result<bool> {
    let secp = Secp256k1::new();

    // Recompute R1 = s*G - e*A
    let e_a = a_pub.mul_tweak(&secp, &proof.e)?;
    let r1 = PublicKey::from_secret_key(&secp, &scalar_to_secret(&proof.s)?)
        .combine(&e_a.negate(&secp))?;

    // Recompute R2 = s*B' - e*C'
    let e_c = c_prime.mul_tweak(&secp, &proof.e)?;
    let r2 = b_prime
        .mul_tweak(&secp, &proof.s)?
        .combine(&e_c.negate(&secp))?;

    // Recompute challenge
    let mut hasher = Sha256::new();
    hasher.update(r1.serialize());
    hasher.update(r2.serialize());
    hasher.update(a_pub.serialize());
    hasher.update(c_prime.serialize());
    let hash = hasher.finalize();
    let e_computed = Scalar::from_be_bytes(hash.into()).map_err(|_| Error::InvalidScalar)?;

    Ok(e_computed == proof.e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_to_curve;

    #[test]
    fn blind_unblind_roundtrip_equals_direct_signature() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let y = hash_to_curve(b"secret");
        let bm = blind_message(&y).unwrap();
        let (c_prime, proof) = blind_sign(&sk, &bm.blinded_point).unwrap();

        assert!(verify_dleq(&bm.blinded_point, &c_prime, &pk, &proof));

        let c = unblind_signature(&c_prime, &bm.blind_factor, &pk).unwrap();
        let direct = y.mul_tweak(&secp, &sk.into()).unwrap();
        assert_eq!(c, direct, "unblinded signature must equal x*Y");
    }

    #[test]
    fn dleq_rejects_tampered_proof() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let y = hash_to_curve(b"secret");
        let bm = blind_message(&y).unwrap();
        let (c_prime, mut proof) = blind_sign(&sk, &bm.blinded_point).unwrap();

        proof.e = random_scalar();
        assert!(!verify_dleq(&bm.blinded_point, &c_prime, &pk, &proof));
    }

    #[test]
    fn dleq_rejects_wrong_key() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());

        let y = hash_to_curve(b"secret");
        let bm = blind_message(&y).unwrap();
        let (c_prime, proof) = blind_sign(&sk, &bm.blinded_point).unwrap();

        let wrong_pk = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rand::thread_rng()));
        assert!(!verify_dleq(&bm.blinded_point, &c_prime, &wrong_pk, &proof));
    }

    #[test]
    fn blinded_message_and_dleq_serde_roundtrip() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let y = hash_to_curve(b"secret");
        let bm = blind_message(&y).unwrap();
        let (_c_prime, proof) = blind_sign(&sk, &bm.blinded_point).unwrap();

        let bm2: BlindedMessage =
            serde_json::from_str(&serde_json::to_string(&bm).unwrap()).unwrap();
        assert!(bm == bm2);

        let proof2: DLEQ = serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
        assert!(proof == proof2);
    }
}
