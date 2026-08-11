use rand::RngCore;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct BlindedMessage {
    pub blinded_point: PublicKey,
    pub blind_factor: Scalar,
}

#[derive(Clone)]
pub struct DLEQ {
    pub e: Scalar,
    pub s: Scalar,
}

fn random_scalar() -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(s) = Scalar::from_be_bytes(bytes) {
            if s != Scalar::ZERO {
                return s;
            }
        }
    }
}

pub fn blind_message(y: &PublicKey) -> BlindedMessage {
    let secp = Secp256k1::new();
    let r = random_scalar();

    let r_g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&r.to_be_bytes()).unwrap());

    let blinded_point = y.combine(&r_g).unwrap();

    BlindedMessage {
        blinded_point,
        blind_factor: r,
    }
}

pub fn blind_sign(privkey: &SecretKey, blinded_point: &PublicKey) -> (PublicKey, DLEQ) {
    let secp = Secp256k1::new();
    let a = Scalar::from_be_bytes(privkey.secret_bytes()).unwrap();

    let c_prime = blinded_point.mul_tweak(&secp, &a).unwrap();

    // Generate DLEQ proof: prove log_G(A) == log_{B'}(C')
    let r = random_scalar(); // nonce
    let r_g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&r.to_be_bytes()).unwrap()); // R1 = r*G
    let r_b = blinded_point.mul_tweak(&secp, &r).unwrap(); // R2 = r*B'

    let a_pub = PublicKey::from_secret_key(&secp, &privkey); // A = a*G

    // Challenge e = hash(R1 || R2 || A || C')
    let mut hasher = Sha256::new();
    hasher.update(r_g.serialize());
    hasher.update(r_b.serialize());
    hasher.update(a_pub.serialize());
    hasher.update(c_prime.serialize());
    let hash = hasher.finalize();

    let e = Scalar::from_be_bytes(hash.into()).unwrap(); // reduce mod order if needed, but secp handles
    let e_sk: SecretKey = SecretKey::from_slice(&e.to_be_bytes()).unwrap();

    // s1 = e*a
    let s1: SecretKey = e_sk.mul_tweak(&a).unwrap();

    // s = r + s1
    let r_sk = SecretKey::from_slice(&r.to_be_bytes()).unwrap();
    let s_sk = r_sk
        .add_tweak(&Scalar::from_be_bytes(s1.secret_bytes()).unwrap())
        .unwrap();
    let s = Scalar::from_be_bytes(s_sk.secret_bytes()).unwrap();

    let proof = DLEQ { e, s };

    (c_prime, proof)
}

pub fn unblind_signature(
    blind_sig: &PublicKey,
    blind_factor: &Scalar,
    mint_pubkey: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();
    let r_k = mint_pubkey.mul_tweak(&secp, blind_factor).unwrap();
    blind_sig.combine(&r_k.negate(&secp)).unwrap()
}

pub fn verify_dleq(
    b_prime: &PublicKey,
    c_prime: &PublicKey,
    a_pub: &PublicKey,
    proof: &DLEQ,
) -> bool {
    let secp = Secp256k1::new();

    // Recompute R1 = s*G - e*A
    let e_a = a_pub.mul_tweak(&secp, &proof.e).unwrap();
    let r1 = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&proof.s.to_be_bytes()).unwrap(),
    )
    .combine(&e_a.negate(&secp))
    .unwrap();

    // Recompute R2 = s*B' - e*C'
    let e_c = c_prime.mul_tweak(&secp, &proof.e).unwrap();
    let r2 = b_prime
        .mul_tweak(&secp, &proof.s)
        .unwrap()
        .combine(&e_c.negate(&secp))
        .unwrap();

    // Recompute challenge
    let mut hasher = Sha256::new();
    hasher.update(r1.serialize());
    hasher.update(r2.serialize());
    hasher.update(a_pub.serialize());
    hasher.update(c_prime.serialize());
    let hash = hasher.finalize();
    let e_computed = Scalar::from_be_bytes(hash.into()).unwrap();

    e_computed == proof.e
}
