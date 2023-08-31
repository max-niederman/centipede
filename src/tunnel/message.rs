use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

use crate::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    pub link: EndpointId,
    pub seq: u64,
    pub packet: &'m [u8],
}

pub const HEADER_SIZE: usize = 4 + 8 + 16;
pub const MTU: usize = 1500;

impl<'m> Message<'m> {
    pub const fn length(&self) -> usize {
        HEADER_SIZE + self.packet.len()
    }

    // TODO: reduce the duplication here

    pub fn parse(buf: &'m [u8]) -> Result<Self, Error> {
        let (nonce, buf) = buf.split_at(12);
        let (tag, packet) = buf.split_at(16);

        let (link, seq) = nonce.split_at(4);

        Ok(Self {
            link: EndpointId(
                u32::from_be_bytes(link.try_into().unwrap())
                    .try_into()
                    .map_err(|_| Error::InvalidEndpoint)?,
            ),
            seq: u64::from_be_bytes(seq.try_into().unwrap()),
            packet,
        })
    }

    pub fn decode(cipher: &ChaCha20Poly1305, buf: &'m mut [u8]) -> Result<Self, Error> {
        let (nonce, buf) = buf.split_at_mut(12);
        let (tag, packet) = buf.split_at_mut(16);

        cipher
            .decrypt_in_place_detached(
                Nonce::from_mut_slice(nonce),
                &[],
                packet,
                Tag::from_mut_slice(tag),
            )
            .map_err(Error::Decryption)?;

        let (link, seq) = nonce.split_at_mut(4);

        Ok(Self {
            link: EndpointId(
                u32::from_be_bytes(link.try_into().unwrap())
                    .try_into()
                    .map_err(|_| Error::InvalidEndpoint)?,
            ),
            seq: u64::from_be_bytes(seq.try_into().unwrap()),
            packet,
        })
    }

    pub fn encode(
        &self,
        cipher: &ChaCha20Poly1305,
        mut buf: &'m mut [u8],
    ) -> Result<&'m [u8], Error> {
        if buf.len() < self.length() {
            return Err(Error::BufferTooSmall);
        }

        buf = &mut buf[..self.length()];

        let (nonce, rest) = buf.split_at_mut(12);
        let (tag_buf, packet) = rest.split_at_mut(16);
        let (link, seq) = nonce.split_at_mut(4);

        link.copy_from_slice(&self.link.0.get().to_be_bytes());
        seq.copy_from_slice(&self.seq.to_be_bytes());
        packet.copy_from_slice(self.packet);

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_mut_slice(nonce), &[], packet)
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

        let mut buf = [0; MTU];
        let message = Message {
            link: EndpointId(0x12345678.try_into().unwrap()),
            seq: 0xabcdef,
            packet: &[0; MTU - HEADER_SIZE],
        };

        message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::decode(&cipher, &mut buf).unwrap();
        assert_eq!(decoded, message);
    }
}
