use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    /// The sequence number of this message.
    pub sequence_number: u64,

    /// The identifier of the sender.
    /// This is the upper 64 bits of the sender's public key.
    pub sender: [u8; 8],

    /// The packet data.
    pub packet: &'m [u8],
}

impl<'m> Message<'m> {
    pub const HEADER_SIZE: usize = 8 + 8 + 16;

    pub const fn length(&self) -> usize {
        Self::HEADER_SIZE + self.packet.len()
    }

    pub fn parse(buf: &'m [u8]) -> Result<Self, Error> {
        let sequence_number = u64::from_be_bytes(buf[..8].try_into().unwrap());
        let sender = buf[8..16].try_into().unwrap();
        let packet = &buf[32..];

        Ok(Self {
            sequence_number,
            sender,
            packet,
        })
    }

    pub fn decode(cipher: &ChaCha20Poly1305, buf: &'m mut [u8]) -> Result<Self, Error> {
        let (header, packet) = buf.split_at_mut(Self::HEADER_SIZE);

        let nonce = &header[..12];
        let tag = &header[16..];

        cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &[], packet, Tag::from_slice(tag))
            .map_err(Error::Decryption)?;

        Self::parse(buf)
    }

    pub fn encode(
        &self,
        cipher: &ChaCha20Poly1305,
        mut buf: &'m mut [u8],
    ) -> Result<&'m mut [u8], Error> {
        if buf.len() < self.length() {
            return Err(Error::BufferTooSmall);
        }

        buf = &mut buf[..self.length()];

        let (header, packet) = buf.split_at_mut(Self::HEADER_SIZE);

        header[..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        header[8..16].copy_from_slice(&self.sender);

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header[..12]), &[], packet)
            .map_err(Error::Encryption)?;

        header[16..].copy_from_slice(&tag);

        Ok(buf)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to decrypt message")]
    Decryption(#[source] chacha20poly1305::Error),

    #[error("failed to encrypt message")]
    Encryption(#[source] chacha20poly1305::Error),

    #[error("buffer too small")]
    BufferTooSmall,

    #[error("message specified invalid endpoint id")]
    InvalidEndpoint,
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;

    #[test]
    fn decode_inverts_encode() {
        let cipher = ChaCha20Poly1305::new(&[0; 32].into());

        let mut buf = [0; 1500];
        let message = Message {
            sequence_number: 0xabcdef,
            sender: [1; 8],
            packet: &[0; 1500 - Message::HEADER_SIZE],
        };

        let datagram = message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::decode(&cipher, datagram).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn parse_inverts_encode_header() {
        let cipher = ChaCha20Poly1305::new(&[0; 32].into());

        let mut buf = [0; 1500];
        let message = Message {
            sequence_number: 0xabcdef,
            sender: [1; 8],
            packet: &[0; 1500 - Message::HEADER_SIZE],
        };

        let datagram = message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::parse(datagram).unwrap();
        assert_eq!(decoded.sender, message.sender);
        assert_eq!(decoded.sequence_number, message.sequence_number);
        assert_ne!(decoded.packet, message.packet);
    }
}
