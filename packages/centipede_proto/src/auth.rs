pub trait Status: crate::seal::Sealed {
    const NAME: &'static str;
}

pub struct Unknown;
impl crate::seal::Sealed for Unknown {}
impl Status for Unknown {
    const NAME: &'static str = "unknown";
}

pub struct Valid;
impl crate::seal::Sealed for Valid {}
impl Status for Valid {
    const NAME: &'static str = "valid";
}

pub struct Invalid;
impl crate::seal::Sealed for Invalid {}
impl Status for Invalid {
    const NAME: &'static str = "invalid";
}
