use rand::RngCore;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

#[derive(Clone)]
pub struct BlindedMessage {
    pub blinded_point: PublicKey,
    pub blind_factor: Scalar,
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

pub fn blind_sign(privkey: &SecretKey, blinded_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(privkey.secret_bytes()).unwrap();
    blinded_point.mul_tweak(&secp, &scalar).unwrap()
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
