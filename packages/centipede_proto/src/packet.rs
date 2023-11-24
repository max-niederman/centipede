use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut, Range, RangeFrom},
};

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
use thiserror::Error;

use crate::auth;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// The buffer containing the message.
    buffer: B,

    /// Marker for the authentication status.
    _auth: PhantomData<A>,
}

// Ranges of the message buffer.
const SEQUENCE_NUMBER_RANGE: Range<usize> = 0..8;
const SENDER_RANGE: Range<usize> = 8..16;
const NONCE_RANGE: Range<usize> = 0..12;
const TAG_RANGE: Range<usize> = 16..32;
const PACKET_RANGE: RangeFrom<usize> = 32..;

impl<B, A> Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
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
    pub fn forget_auth(self) -> Message<B, auth::Unknown> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
        }
    }

    /// Invalidate the message's authentication status.
    pub fn invalidate(self) -> Message<B, auth::Invalid> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
        }
    }

    /// Deconstruct the message into its underlying buffer.
    pub fn into_buffer(self) -> B {
        self.buffer
    }

    /// Access the message's underlying buffer.
    pub fn as_buffer(&self) -> &B {
        &self.buffer
    }

    /// Create an owned message using a `Vec`.
    pub fn to_owned(&self) -> Message<Vec<u8>, A> {
        Message {
            buffer: (*self.buffer).into(),
            _auth: self._auth,
        }
    }
}

impl<B> Message<B, auth::Unknown>
where
    B: Deref<Target = [u8]>,
{
    /// Create a message from a buffer.
    ///
    /// This validates the buffer's structure, but does not verify its signature.
    pub fn from_buffer(buffer: B) -> Result<Self, Error> {
        if buffer.len() < 32 {
            return Err(Error::BufferTooSmall);
        }

        Ok(Self {
            buffer,
            _auth: PhantomData,
        })
    }

    /// Get a mutable reference to the message's underlying buffer.
    ///
    /// Used to construct messages in-place.
    pub fn as_buffer_mut(&mut self) -> &mut B {
        &mut self.buffer
    }

    /// Attest that the message is valid, without validating its signature.
    ///
    /// This function should be treated with the utmost caution.
    pub fn attest(self) -> Message<B, auth::Valid> {
        Message {
            buffer: self.buffer,
            _auth: PhantomData,
        }
    }

    /// Decrypt the message and validate its tag.
    ///
    /// The passed cipher must correspond to the sender's claimed ID.
    pub fn decrypt_in_place(
        mut self,
        cipher: &ChaCha20Poly1305,
    ) -> Result<Message<B, auth::Valid>, DecryptionError<B>>
    where
        B: DerefMut<Target = [u8]>,
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
            }),
            Err(reason) => Err(DecryptionError {
                message: self.invalidate(),
                reason,
            }),
        }
    }
}

impl<B> Message<B, auth::Valid>
where
    B: Deref<Target = [u8]>,
{
    /// The validated sequence number of this message.
    pub fn sequence_number(&self) -> u64 {
        self.claimed_sequence_number()
    }

    /// The validated sender ID of this message.
    pub fn sender(&self) -> [u8; 8] {
        self.claimed_sender()
    }

    /// The validated packet data.
    pub fn packet(&self) -> &[u8] {
        &self.buffer[PACKET_RANGE]
    }

    /// Encrypt the message, fill in its tag, and return its buffer.
    pub fn encrypt_in_place(mut self, cipher: &ChaCha20Poly1305) -> B
    where
        B: DerefMut<Target = [u8]>,
    {
        let (header, packet) = self.buffer.split_at_mut(32);

        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&header[NONCE_RANGE]), &[], packet)
            .unwrap();

        header[TAG_RANGE].copy_from_slice(&tag);

        self.buffer
    }
}

impl<B, A> Debug for Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Message {{ seq: {}, sender: {:#x}, packet: [..][{}] }}",
            self.claimed_sequence_number(),
            u64::from_be_bytes(self.claimed_sender()),
            self.buffer[PACKET_RANGE].len()
        )
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("attempted to parse a packet message from too small a buffer")]
    BufferTooSmall,

    #[error(transparent)]
    Decryption(DecryptionError<Vec<u8>>),
}

/// An error representing a failure to authenticate a packet message.
#[derive(Debug, Error)]
#[error("failed to authenticate packet message: {message:?}")]
pub struct DecryptionError<B: Deref<Target = [u8]>> {
    pub message: Message<B, auth::Invalid>,

    #[source]
    pub reason: chacha20poly1305::Error,
}

impl<B> From<DecryptionError<B>> for Error
where
    B: Deref<Target = [u8]>,
{
    fn from(error: DecryptionError<B>) -> Self {
        Self::Decryption(DecryptionError {
            message: error.message.to_owned(),
            reason: error.reason,
        })
    }
}
