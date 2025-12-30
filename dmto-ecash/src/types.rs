use secp256k1::PublicKey;

#[derive(Clone)]
pub struct Note {
    pub value: u64,
    pub secret: Vec<u8>,
    pub y: PublicKey,
    pub c: PublicKey,
}
