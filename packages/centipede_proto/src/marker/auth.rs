use super::seal;

pub trait Status: seal::Sealed {
    const NAME: &'static str;
}

pub struct Unknown;
impl seal::Sealed for Unknown {}
impl Status for Unknown {
    const NAME: &'static str = "unknown";
}

pub struct Valid;
impl seal::Sealed for Valid {}
impl Status for Valid {
    const NAME: &'static str = "valid";
}

pub struct Invalid;
impl seal::Sealed for Invalid {}
impl Status for Invalid {
    const NAME: &'static str = "invalid";
}
