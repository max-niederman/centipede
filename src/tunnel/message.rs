use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

use crate::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    /// The endpoint to which this message is addressed.
    pub endpoint: EndpointId,
    /// The sequence number of this message.
    pub sequence_number: u64,
    /// The packet data.
    pub packet: &'m [u8],
}

impl<'m> Message<'m> {
    pub const HEADER_SIZE: usize = 4 + 8 + 16;

    pub const fn length(&self) -> usize {
        Self::HEADER_SIZE + self.packet.len()
    }

    // TODO: reduce the duplication here

    pub fn parse(buf: &'m [u8]) -> Result<Self, Error> {
        let (&endpoint, buf) = buf.split_array_ref::<4>();
        let (&sequence_number, buf) = buf.split_array_ref::<8>();
        let (_tag, packet) = buf.split_at(16);

        let endpoint = EndpointId(
            u32::from_be_bytes(endpoint)
                .try_into()
                .map_err(|_| Error::InvalidEndpoint)?,
        );

        let sequence_number = u64::from_be_bytes(sequence_number);

        Ok(Self {
            endpoint,
            sequence_number,
            packet,
        })
    }

    pub fn decode(cipher: &ChaCha20Poly1305, buf: &'m mut [u8]) -> Result<Self, Error> {
        let (nonce, buf) = buf.split_at_mut(4 + 8);
        let (tag, packet) = buf.split_at_mut(16);

        cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &[], packet, Tag::from_slice(tag))
            .map_err(Error::Decryption)?;

        let (&endpoint, sequence_number) = nonce.split_array_ref::<4>();

        let endpoint = EndpointId(
            u32::from_be_bytes(endpoint)
                .try_into()
                .map_err(|_| Error::InvalidEndpoint)?,
        );

        let sequence_number = u64::from_be_bytes(sequence_number.try_into().unwrap());

        Ok(Self {
            endpoint,
            sequence_number,
            packet,
        })
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

        let (nonce, rest) = buf.split_at_mut(4 + 8);
        let (tag_buf, packet) = rest.split_at_mut(16);

        packet.copy_from_slice(self.packet);

        let (endpoint, sequence_number) = nonce.split_at_mut(4);

        endpoint.copy_from_slice(&self.endpoint.0.get().to_be_bytes());
        sequence_number.copy_from_slice(&self.sequence_number.to_be_bytes());

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), &[], packet)
            .map_err(Error::Encryption)?;

        tag_buf.copy_from_slice(&tag);

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
            endpoint: EndpointId(0x12345678.try_into().unwrap()),
            sequence_number: 0xabcdef,
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
            endpoint: EndpointId(0x12345678.try_into().unwrap()),
            sequence_number: 0xabcdef,
            packet: &[0; 1500 - Message::HEADER_SIZE],
        };

        let datagram = message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::parse(datagram).unwrap();
        assert_eq!(decoded.endpoint, message.endpoint);
        assert_eq!(decoded.sequence_number, message.sequence_number);
        assert_ne!(decoded.packet, message.packet);
    }
}
