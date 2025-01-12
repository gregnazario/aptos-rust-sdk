pub trait PrivateKey<P: PublicKey<S>, S: Signature> {
    fn sign(&self, bytes: &[u8]) -> S;

    fn public_key(&self) -> P;
}

pub trait PublicKey<S: Signature> {
    fn verify(&self, payload: &[u8], signature: &S) -> anyhow::Result<()>;
}

pub trait Signature {}
