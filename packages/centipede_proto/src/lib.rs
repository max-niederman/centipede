pub mod control;
pub mod marker;
pub mod packet;

use std::ops::Deref;

use thiserror::Error;

pub use control::Message as ControlMessage;
pub use packet::Message as PacketMessage;

/// Discriminate between control and packet messages.
pub fn discriminate<B: Deref<Target = [u8]>>(
    buffer: B,
) -> Result<MessageDiscriminant, DiscriminationError> {
    let bytes = buffer.get(0..8).ok_or(DiscriminationError::TooShort)?;
    let discriminant = u64::from_be_bytes(bytes.try_into().unwrap());

    match discriminant {
        0x0000_0000_0000_0000..=0x7FFF_FFFF_FFFF_FFFF => Ok(MessageDiscriminant::Packet),
        0x8000_0000_0000_0000 => Ok(MessageDiscriminant::Control),
        discriminant => Err(DiscriminationError::InvalidDiscriminant(discriminant)),
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageDiscriminant {
    Control,
    Packet,
}

#[derive(Debug, Error)]
pub enum DiscriminationError {
    #[error("message is too short")]
    TooShort,

    #[error("nonexistent message discriminant: {0:x}")]
    InvalidDiscriminant(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_discriminant() {
        assert!(matches!(
            discriminate([].as_slice()),
            Err(DiscriminationError::TooShort)
        ));
    }

    #[test]
    fn invalid_discriminant() {
        assert!(matches!(
            discriminate([0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice()),
            Err(DiscriminationError::InvalidDiscriminant(0xff00000000000000))
        ));
    }
}
