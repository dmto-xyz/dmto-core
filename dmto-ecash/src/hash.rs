use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub fn hash_to_curve(secret: &[u8]) -> PublicKey {
    let secp = Secp256k1::new();
    let mut ctr = 0u32;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"ecash_hash_to_curve");
        hasher.update(secret);
        hasher.update(ctr.to_be_bytes());
        let hash = hasher.finalize();

        if let Ok(sk) = SecretKey::from_slice(&hash) {
            return PublicKey::from_secret_key(&secp, &sk);
        }
        ctr += 1;
    }
}
