use std::{
    fmt::Debug,
    io,
    marker::PhantomData,
    ops::{Deref, DerefMut, Range, RangeFrom},
};

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

use crate::marker::{auth, text};

/// A packet message.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<B, A, T>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
    T: text::Kind,
{
    /// The buffer containing the message.
    buffer: B,

    /// Marker for the authentication status.
    _auth: PhantomData<A>,

    /// Marker for the text kind.
    _text: PhantomData<T>,
}

impl<B, A, T> Message<B, A, T>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
    T: text::Kind,
{
    /// The claimed sequence number of this message.
    pub fn claimed_sequence_number(&self) -> u64 {
        u64::from_be_bytes(self.buffer[SEQUENCE_NUMBER_RANGE].try_into().unwrap())
    }

    /// The claimed sender ID of this message.
    pub fn claimed_sender(&self) -> [u8; 8] {
        self.buffer[SENDER_RANGE].try_into().unwrap()
    }

    /// Forget the message's authentication status.
    pub fn forget_auth(self) -> Message<B, auth::Unknown, T> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }

    /// Attest that the message is valid, without validating its signature.
    ///
    /// This function should be treated with the utmost caution.
    pub unsafe fn attest(self) -> Message<B, auth::Valid, T> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }

    /// Invalidate the message's authentication status.
    pub fn invalidate(self) -> Message<B, auth::Invalid, T> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }

    /// Create a message from a buffer without validating its structure or authenticity.
    ///
    /// This function should be treated with the utmost caution.
    pub const unsafe fn from_buffer_unchecked(buffer: B) -> Self {
        Self {
            buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }

    /// Interpret the message buffer as a byte slice.
    pub fn as_ref(&self) -> Message<&'_ [u8], A, T> {
        Message {
            buffer: &self.buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }

    /// Deconstruct the message into its underlying buffer.
    pub fn to_buffer(self) -> B {
        self.buffer
    }

    /// Access the message's underlying buffer.
    pub fn as_buffer(&self) -> &B {
        &self.buffer
    }
}

impl<B, A> Message<B, A, text::Ciphertext>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// Get the ciphertext packet data.
    pub fn claimed_packet_ciphertext(&self) -> &[u8] {
        &self.buffer[PACKET_RANGE]
    }
}

impl<B, A> Message<B, A, text::Plaintext>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// Get the plaintext packet data.
    pub fn claimed_packet_plaintext(&self) -> &[u8] {
        &self.buffer[PACKET_RANGE]
    }
}

impl<B> Message<B, auth::Unknown, text::Ciphertext>
where
    B: Deref<Target = [u8]>,
{
    /// Deserialize an encrypted message from a buffer.
    ///
    /// This validates the buffer's structure, but does not verify its signature.
    pub fn from_buffer(buffer: B) -> Result<Self, ParseError> {
        if buffer.len() < PACKET_RANGE.start {
            return Err(ParseError::BufferTooSmall);
        }

        Ok(unsafe { Self::from_buffer_unchecked(buffer) })
    }
}

impl<B, A> Message<B, A, text::Ciphertext>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// Decrypt the message and validate its tag.
    ///
    /// The passed cipher must correspond to the sender's claimed ID.
    pub fn decrypt_in_place(
        mut self,
        cipher: &ChaCha20Poly1305,
    ) -> Result<Message<B, auth::Valid, text::Plaintext>, DecryptionError<B>>
    where
        B: DerefMut,
    {
        let (header, packet) = self.buffer.split_at_mut(32);

        match cipher.decrypt_in_place_detached(
            Nonce::from_slice(&header[NONCE_RANGE]),
            &[],
            packet,
            Tag::from_slice(&header[TAG_RANGE]),
        ) {
            Ok(()) => Ok(Message {
                buffer: self.buffer,
                _auth: PhantomData,
                _text: PhantomData,
            }),
            Err(reason) => Err(DecryptionError {
                message: self.invalidate(),
                reason,
            }),
        }
    }
}

impl<B, T> Message<B, auth::Valid, T>
where
    B: Deref<Target = [u8]>,
    T: text::Kind,
{
    /// The validated sequence number of this message.
    pub fn sequence_number(&self) -> u64 {
        self.claimed_sequence_number()
    }

    /// The validated sender ID of this message.
    pub fn sender(&self) -> [u8; 8] {
        self.claimed_sender()
    }
}

impl<B> Message<B, auth::Valid, text::Ciphertext>
where
    B: Deref<Target = [u8]>,
{
    /// The validated ciphertext packet data.
    pub fn packet_ciphertext(&self) -> &[u8] {
        &self.buffer[PACKET_RANGE]
    }
}

impl<B> Message<B, auth::Valid, text::Plaintext>
where
    B: Deref<Target = [u8]>,
{
    /// The validated plaintext packet data.
    pub fn packet_plaintext(&self) -> &[u8] {
        &self.buffer[PACKET_RANGE]
    }

    /// Encrypt the message, fill in its tag, and return its buffer.
    pub fn encrypt_in_place(
        mut self,
        cipher: &ChaCha20Poly1305,
    ) -> Message<B, auth::Valid, text::Ciphertext>
    where
        B: DerefMut,
    {
        let (header, packet) = self.buffer.split_at_mut(32);

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header[NONCE_RANGE]), &[], packet)
            .unwrap();

        header[TAG_RANGE].copy_from_slice(&tag);

        Message {
            buffer: self.buffer,
            _auth: PhantomData,
            _text: PhantomData,
        }
    }
}

impl Message<Vec<u8>, auth::Valid, text::Plaintext> {
    /// Measure the buffer size needed to hold a message with the given packet size.
    pub const fn measure(packet_size: usize) -> usize {
        PACKET_RANGE.start + packet_size
    }

    /// Create a new message with an empty packet in a scratch buffer using the given metadata.
    pub fn new_in(sequence_number: u64, sender: [u8; 8], mut buffer: Vec<u8>) -> Self {
        buffer.clear();
        buffer.extend_from_slice(&sequence_number.to_be_bytes());
        buffer.extend_from_slice(&sender);
        buffer.resize(32, 0);

        unsafe { Self::from_buffer_unchecked(buffer) }
    }

    /// Create a new message backed by a [`Vec<u8>`] with capacity for the given packet size using the given metadata.
    pub fn new_with_capacity(sequence_number: u64, sender: [u8; 8], packet_size: usize) -> Self {
        Self::new_in(
            sequence_number,
            sender,
            Vec::with_capacity(PACKET_RANGE.start + packet_size),
        )
    }

    /// Create a new message backed by a [`Vec<u8>`] using the given metadata.
    pub fn new(sequence_number: u64, sender: [u8; 8]) -> Self {
        Self::new_with_capacity(sequence_number, sender, 0)
    }

    /// Overwrite the message's packet data from an iterator.
    pub fn overwrite_packet(&mut self, iter: impl IntoIterator<Item = u8>) {
        let iter = iter.into_iter();

        self.reserve_packet(iter.size_hint().0);

        self.buffer.truncate(PACKET_RANGE.start);
        self.buffer.extend(iter);
    }

    /// Reserve space for a packet of the given size.
    pub fn reserve_packet(&mut self, size: usize) {
        self.buffer.reserve(PACKET_RANGE.start + size);
    }

    /// Allocate space for a packet of the given size and return a mutable reference to it.
    pub fn allocate_packet(&mut self, size: usize) -> &mut [u8] {
        self.buffer.resize(PACKET_RANGE.start + size, 0);
        &mut self.buffer[PACKET_RANGE]
    }
}

impl<B, A, T> Debug for Message<B, A, T>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
    T: text::Kind,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message {{ seq: {}, sender: {:#x}, packet: [..][{}], _auth: {}, _text: {} }}",
            self.claimed_sequence_number(),
            u64::from_be_bytes(self.claimed_sender()),
            self.buffer[PACKET_RANGE].len(),
            A::NAME,
            T::NAME
        )
    }
}

// Ranges of the message buffer.
const SEQUENCE_NUMBER_RANGE: Range<usize> = 0..8;
const SENDER_RANGE: Range<usize> = 8..16;
const NONCE_RANGE: Range<usize> = 0..12;
const TAG_RANGE: Range<usize> = 16..32;
const PACKET_RANGE: RangeFrom<usize> = 32..;

/// A mutable reference to a [`Vec<u8>`] that can be used as a packet message buffer.
pub struct ByteVecMut<'v>(pub &'v mut Vec<u8>);

impl<'v> Deref for ByteVecMut<'v> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'v> DerefMut for ByteVecMut<'v> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

/// An error representing a failure to parse a packet message.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("attempted to parse a packet message from too small a buffer")]
    BufferTooSmall,
    #[error("attempted to parse a packet message with an invalid tag {0:x}")]
    InvalidTag(u64),
}

/// An error representing a failure to authenticate a packet message.
#[derive(Debug, Error)]
#[error("failed to authenticate packet message: {message:?}")]
pub struct DecryptionError<B: Deref<Target = [u8]>> {
    pub message: Message<B, auth::Invalid, text::Ciphertext>,

    #[source]
    pub reason: chacha20poly1305::Error,
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::KeyInit;

    use crate::{discriminate, MessageDiscriminant};

    use super::*;

    const PACKET: &[u8] = b"hello world";
    const ZERO_COPY_PACKET: &[u8] = b"hello zero-copy";

    #[test]
    fn construct_in_place() {
        let mut message = Message::new(42, [1; 8]);

        assert_eq!(message.claimed_sequence_number(), 42);
        assert_eq!(message.claimed_sender(), [1; 8]);
        assert_eq!(message.claimed_packet_plaintext(), &[]);

        message.overwrite_packet(PACKET.iter().copied());

        assert_eq!(message.claimed_packet_plaintext(), b"hello world");

        message
            .allocate_packet(ZERO_COPY_PACKET.len())
            .copy_from_slice(ZERO_COPY_PACKET);

        assert_eq!(message.claimed_packet_plaintext(), b"hello zero-copy");
    }

    #[test]
    fn encrypt_and_decrypt_in_place() {
        let mut message = Message::new(1729, [42; 8]);

        message.overwrite_packet(PACKET.iter().copied());

        let cipher = ChaCha20Poly1305::new((&[42; 32]).into());

        let ciphertext_message = message.encrypt_in_place(&cipher);

        assert_eq!(ciphertext_message.claimed_sequence_number(), 1729);
        assert_eq!(ciphertext_message.claimed_sender(), [42; 8]);
        assert_ne!(ciphertext_message.claimed_packet_ciphertext(), PACKET);

        let plaintext_message = ciphertext_message.decrypt_in_place(&cipher).unwrap();

        assert_eq!(plaintext_message.claimed_sequence_number(), 1729);
        assert_eq!(plaintext_message.claimed_sender(), [42; 8]);
        assert_eq!(plaintext_message.claimed_packet_plaintext(), PACKET);
    }

    #[test]
    fn discriminate_packet() {
        let plaintext = Message::new(42, [1; 8]);
        let cipher = ChaCha20Poly1305::new((&[42; 32]).into());
        let ciphertext = plaintext.encrypt_in_place(&cipher);

        assert_eq!(
            discriminate(ciphertext.as_buffer().as_slice()).unwrap(),
            MessageDiscriminant::Packet
        );
    }
}
