use std::{mem, num::NonZeroU32};

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

use crate::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    /// The endpoint to which this message is addressed.
    pub endpoint: EndpointId,
    /// The sequence number of this message.
    pub sequence_number: u64,
    /// The endpoint whose address the recipient should update.
    pub opposite_endpoint: Option<EndpointId>,
    /// The packet data.
    pub packet: &'m [u8],
}

pub const HEADER_SIZE: usize = 4 + 8 + 4 + 16;
pub const MTU: usize = 1500;

impl<'m> Message<'m> {
    pub const fn length(&self) -> usize {
        HEADER_SIZE + self.packet.len()
    }

    // TODO: reduce the duplication here

    pub fn parse(buf: &'m [u8]) -> Result<Self, Error> {
        let (endpoint, buf) = buf.split_at(4);
        let (sequence_number, buf) = buf.split_at(8);
        let (opposite_endpoint, packet) = buf.split_at(4);
        let (tag, buf) = buf.split_at(16);

        let endpoint = EndpointId(
            u32::from_be_bytes(endpoint.try_into().unwrap())
                .try_into()
                .map_err(|_| Error::InvalidEndpoint)?,
        );

        let sequence_number = u64::from_be_bytes(sequence_number.try_into().unwrap());

        let opposite_endpoint = unsafe {
            mem::transmute::<u32, Option<NonZeroU32>>(u32::from_be_bytes(
                opposite_endpoint.try_into().unwrap(),
            ))
        }
        .map(EndpointId);

        Ok(Self {
            endpoint,
            sequence_number,
            opposite_endpoint,
            packet,
        })
    }

    pub fn decode(cipher: &ChaCha20Poly1305, buf: &'m mut [u8]) -> Result<Self, Error> {
        let (nonce, buf) = buf.split_at_mut(4 + 8);
        let (associated_data, buf) = buf.split_at_mut(4);
        let (tag, packet) = buf.split_at_mut(16);

        cipher
            .decrypt_in_place_detached(
                Nonce::from_mut_slice(nonce),
                &associated_data,
                packet,
                Tag::from_mut_slice(tag),
            )
            .map_err(Error::Decryption)?;

        let (endpoint, sequence_number) = nonce.split_at(4);
        let opposite_endpoint = associated_data;

        let endpoint = EndpointId(
            u32::from_be_bytes(endpoint.try_into().unwrap())
                .try_into()
                .map_err(|_| Error::InvalidEndpoint)?,
        );

        let sequence_number = u64::from_be_bytes(sequence_number.try_into().unwrap());

        let opposite_endpoint = unsafe {
            mem::transmute::<u32, Option<NonZeroU32>>(u32::from_be_bytes(
                opposite_endpoint.try_into().unwrap(),
            ))
        }
        .map(EndpointId);

        Ok(Self {
            endpoint,
            sequence_number,
            opposite_endpoint,
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

        let (nonce, buf) = buf.split_at_mut(4 + 8);
        let (associated_data, buf) = buf.split_at_mut(4);
        let (tag_buf, packet) = buf.split_at_mut(16);

        let (endpoint, sequence_number) = nonce.split_at_mut(4);
        let opposite_endpoint = associated_data;

        endpoint.copy_from_slice(&self.endpoint.0.get().to_be_bytes());
        sequence_number.copy_from_slice(&self.sequence_number.to_be_bytes());
        opposite_endpoint.copy_from_slice(
            &self
                .opposite_endpoint
                .map(|id| id.0.get().to_be_bytes())
                .unwrap_or([0; 4]),
        );

        let associated_data = opposite_endpoint;

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_mut_slice(nonce), &associated_data, packet)
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
            endpoint: EndpointId(0x12345678.try_into().unwrap()),
            sequence_number: 0xabcdef,
            opposite_endpoint: Some(EndpointId(0x87654321.try_into().unwrap())),
            packet: &[0; MTU - HEADER_SIZE],
        };

        message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::decode(&cipher, &mut buf).unwrap();
        assert_eq!(decoded, message);
    }
}
