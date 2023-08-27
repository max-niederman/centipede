use std::io::Write;

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};

use crate::{dispatcher, LinkId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<'m> {
    pub link: LinkId,
    pub dispatcher_nonce: dispatcher::Nonce,
    pub packet: &'m [u8],
}

impl<'m> Message<'m> {
    pub const fn length(&self) -> usize {
        4 + 8 + 16 + self.packet.len()
    }
}

pub fn decode<'m>(
    cipher: &ChaCha20Poly1305,
    mut buf: &'m mut [u8],
) -> Result<Message<'m>, chacha20poly1305::Error> {
    let (nonce, buf) = buf.split_at_mut(12);
    let (tag, packet) = buf.split_at_mut(16);

    cipher.decrypt_in_place_detached(
        Nonce::from_mut_slice(nonce),
        &[],
        packet,
        Tag::from_mut_slice(tag),
    )?;

    let (link, dispatcher_nonce) = nonce.split_at_mut(4);

    Ok(Message {
        link: LinkId(u32::from_be_bytes(link.try_into().unwrap())),
        dispatcher_nonce: dispatcher_nonce.try_into().unwrap(),
        packet,
    })
}

pub fn encode<'m>(
    cipher: &ChaCha20Poly1305,
    mut buf: &'m mut [u8],
    message: Message<'m>,
) -> Result<&'m [u8], chacha20poly1305::Error> {
    assert!(buf.len() >= message.length());
    buf = &mut buf[..message.length()];

    let (nonce, rest) = buf.split_at_mut(12);
    let (tag_buf, packet) = rest.split_at_mut(16);
    let (link, dispatcher_nonce) = nonce.split_at_mut(4);

    link.copy_from_slice(&message.link.to_be_bytes());
    dispatcher_nonce.copy_from_slice(&message.dispatcher_nonce);
    packet.copy_from_slice(message.packet);

    let tag = cipher.encrypt_in_place_detached(Nonce::from_mut_slice(nonce), &[], packet)?;

    tag_buf.copy_from_slice(&tag);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use super::*;
    use crate::dispatcher;

    #[test]
    fn decode_inverts_encode() {
        let cipher = ChaCha20Poly1305::new(&[0; 32].into());

        let mut buf = [0; 1500];
        let message = Message {
            link: LinkId(0x12345678),
            dispatcher_nonce: [0; 8],
            packet: &[0; 1500 - 4 - 8 - 16],
        };

        encode(&cipher, &mut buf, message).unwrap();

        let decoded = decode(&cipher, &mut buf).unwrap();
        assert_eq!(decoded, message);
    }
}
