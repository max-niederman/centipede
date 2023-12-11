use super::seal;

pub trait Kind: seal::Sealed {
    const NAME: &'static str;
}

pub struct Ciphertext;
impl seal::Sealed for Ciphertext {}
impl Kind for Ciphertext {
    const NAME: &'static str = "valid";
}

pub struct Plaintext;
impl seal::Sealed for Plaintext {}
impl Kind for Plaintext {
    const NAME: &'static str = "invalid";
}
