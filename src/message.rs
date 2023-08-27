use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};

use crate::{dispatcher, LinkId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    pub link: LinkId,
    pub dispatcher_nonce: dispatcher::Nonce,
    pub packet: &'m [u8],
}

pub const HEADER_SIZE: usize = 4 + 8 + 16;
pub const MTU: usize = 1500;

impl<'m> Message<'m> {
    pub const fn length(&self) -> usize {
        HEADER_SIZE + self.packet.len()
    }

    pub fn decode(
        cipher: &ChaCha20Poly1305,
        buf: &'m mut [u8],
    ) -> Result<Self, chacha20poly1305::Error> {
        let (nonce, buf) = buf.split_at_mut(12);
        let (tag, packet) = buf.split_at_mut(16);

        cipher.decrypt_in_place_detached(
            Nonce::from_mut_slice(nonce),
            &[],
            packet,
            Tag::from_mut_slice(tag),
        )?;

        let (link, dispatcher_nonce) = nonce.split_at_mut(4);

        Ok(Self {
            link: LinkId(u32::from_be_bytes(link.try_into().unwrap())),
            dispatcher_nonce: dispatcher_nonce.try_into().unwrap(),
            packet,
        })
    }

    pub fn encode(
        &self,
        cipher: &ChaCha20Poly1305,
        mut buf: &'m mut [u8],
    ) -> Result<&'m [u8], chacha20poly1305::Error> {
        assert!(buf.len() >= self.length());
        buf = &mut buf[..self.length()];

        let (nonce, rest) = buf.split_at_mut(12);
        let (tag_buf, packet) = rest.split_at_mut(16);
        let (link, dispatcher_nonce) = nonce.split_at_mut(4);

        link.copy_from_slice(&self.link.to_be_bytes());
        dispatcher_nonce.copy_from_slice(&self.dispatcher_nonce);
        packet.copy_from_slice(self.packet);

        let tag = cipher.encrypt_in_place_detached(Nonce::from_mut_slice(nonce), &[], packet)?;

        tag_buf.copy_from_slice(&tag);

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;
    use crate::dispatcher;

    #[test]
    fn decode_inverts_encode() {
        let cipher = ChaCha20Poly1305::new(&[0; 32].into());

        let mut buf = [0; MTU];
        let message = Message {
            link: LinkId(0x12345678),
            dispatcher_nonce: [0; 8],
            packet: &[0; MTU - 4 - 8 - 16],
        };

        message.encode(&cipher, &mut buf).unwrap();

        let decoded = Message::decode(&cipher, &mut buf).unwrap();
        assert_eq!(decoded, message);
    }
}
