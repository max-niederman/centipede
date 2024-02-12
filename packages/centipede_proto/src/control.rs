use std::{fmt::Debug, marker::PhantomData, ops::Deref, time::Duration};

use ed25519_dalek::{ed25519::signature::Keypair, Signer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::marker::auth;

/// A parsed control message used to establish and maintain a connection.
#[derive(Clone, PartialEq, Eq)]
pub struct Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// The raw message buffer.
    buffer: B,

    /// The sender's claimed public key.
    sender: ed25519_dalek::VerifyingKey,

    /// The recipient's claimed public key.
    recipient: ed25519_dalek::VerifyingKey,

    /// The message's signature.
    signature: ed25519_dalek::Signature,

    /// The content of the message
    content: Content,

    /// Marker for the authentication status.
    _auth: PhantomData<A>,
}

/// The body of a control message.
/// Carries the actual content without authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    /// Initiate a connection.
    Initiate {
        /// Timestamp of the initiation **on the initiator's clock**, measured from the UNIX epoch.
        /// Used to identify and order the handshake, and prevent replay attacks.
        handshake_timestamp: Duration,

        /// The initiator's ECDH public key.
        ecdh_public_key: x25519_dalek::PublicKey,

        /// The maximum time that the sender is willing to wait between heartbeats.
        max_heartbeat_interval: Duration,
    },

    /// Acknowledge a connection.
    InitiateAcknowledge {
        /// Timestamp of the initiation **on the initiator's clock**, measured from the UNIX epoch.
        /// Used to match the acknowledgement to the initiation.
        handshake_timestamp: Duration,

        /// The responder's ECDH public key.
        ecdh_public_key: x25519_dalek::PublicKey,

        /// The maximum time that the sender is willing to wait between heartbeats.
        max_heartbeat_interval: Duration,
    },

    /// Inform the receiver that the initiator is listening on
    /// (and reachable at) the address from which the message was sent.
    Heartbeat {
        /// The time at which the heartbeat was sent **on the sender's clock**, measured from the UNIX epoch.
        /// Note that this is _not_ compared to the receiver's clock, but instead used
        /// to discard old heartbeats (again by the sender's reckoning), preventing replay attacks.
        timestamp: Duration,
    },
}

impl<B, A> Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    /// The claimed sender public key of this message.
    pub fn claimed_sender(&self) -> &ed25519_dalek::VerifyingKey {
        &self.sender
    }

    /// The claimed recipient public key of this message.
    pub fn claimed_recipient(&self) -> &ed25519_dalek::VerifyingKey {
        &self.recipient
    }

    /// The claimed content of this message.
    pub fn claimed_content(&self) -> &Content {
        &self.content
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

impl<B> Message<B, auth::Unknown>
where
    B: Deref<Target = [u8]>,
{
    /// Parse a message from a buffer, but do not authenticate it.
    pub fn deserialize(buffer: B) -> Result<Self, ParseError> {
        if buffer.len() < CONTENT_RANGE.start {
            return Err(ParseError::BufferTooSmall);
        }

        if buffer[TAG_RANGE] != u64::to_be_bytes(CONTROL_TAG) {
            return Err(ParseError::Tag(u64::from_be_bytes(
                buffer[TAG_RANGE].try_into().unwrap(),
            )));
        }

        Ok(Self {
            sender: ed25519_dalek::VerifyingKey::from_bytes(
                &buffer[SENDER_KEY_RANGE].try_into().unwrap(),
            )
            .map_err(ParseError::SenderKey)?,
            recipient: ed25519_dalek::VerifyingKey::from_bytes(
                &buffer[RECIPIENT_KEY_RANGE].try_into().unwrap(),
            )
            .map_err(ParseError::RecipientKey)?,
            signature: ed25519_dalek::Signature::from_bytes(
                &buffer[SIGNATURE_RANGE].try_into().unwrap(),
            ),
            content: bincode::deserialize(&buffer[CONTENT_RANGE]).map_err(ParseError::Content)?,
            buffer,
            _auth: PhantomData::<auth::Unknown>,
        })
    }

    /// Authenticate the message, consuming the message and
    /// creating a new one with the appropriate authentication status.
    pub fn authenticate(self) -> Result<Message<B, auth::Valid>, AuthenticateError<B>> {
        match self
            .claimed_sender()
            .verify_strict(&self.buffer[SIGNED_RANGE], &self.signature)
        {
            Ok(_) => Ok(Message {
                buffer: self.buffer,
                sender: self.sender,
                recipient: self.recipient,
                signature: self.signature,
                content: self.content,
                _auth: PhantomData::<auth::Valid>,
            }),
            Err(err) => Err(AuthenticateError {
                message: Box::new(Message {
                    buffer: self.buffer,
                    sender: self.sender,
                    recipient: self.recipient,
                    signature: self.signature,
                    content: self.content,
                    _auth: PhantomData::<auth::Invalid>,
                }),
                reason: err,
            }),
        }
    }
}

impl<B> Message<B, auth::Valid>
where
    B: Deref<Target = [u8]>,
{
    /// Get the verified sender public key of this message.
    pub fn sender(&self) -> &ed25519_dalek::VerifyingKey {
        self.claimed_sender()
    }

    /// Get the verified recipient public key of this message.
    pub fn recipient(&self) -> &ed25519_dalek::VerifyingKey {
        self.claimed_recipient()
    }

    /// Get the verified content of this message.
    pub fn content(&self) -> &Content {
        self.claimed_content()
    }
}

impl Message<Vec<u8>, auth::Valid> {
    /// Construct a new control message from a signing key, recipient public key, and its content.
    pub fn new(
        sender_signing_key: ed25519_dalek::SigningKey,
        recipient_public_key: ed25519_dalek::VerifyingKey,
        content: Content,
    ) -> Self {
        let mut buffer =
            vec![0; CONTENT_RANGE.start + bincode::serialized_size(&content).unwrap() as usize];

        buffer[TAG_RANGE].copy_from_slice(&u64::to_be_bytes(CONTROL_TAG));
        buffer[SENDER_KEY_RANGE].copy_from_slice(sender_signing_key.verifying_key().as_bytes());
        buffer[RECIPIENT_KEY_RANGE].copy_from_slice(recipient_public_key.as_bytes());
        bincode::serialize_into(&mut buffer[CONTENT_RANGE], &content).unwrap();

        let signature = sender_signing_key.sign(&buffer[SIGNED_RANGE]);
        buffer[SIGNATURE_RANGE].copy_from_slice(&signature.to_bytes());

        Self {
            sender: sender_signing_key.verifying_key(),
            recipient: recipient_public_key,
            signature,
            content,
            buffer,
            _auth: PhantomData::<auth::Valid>,
        }
    }
}

impl<B, A> Debug for Message<B, A>
where
    B: Deref<Target = [u8]>,
    A: auth::Status,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .field("signature", &self.signature)
            .field("content", &self.content)
            .field("_auth", &A::NAME)
            .finish()
    }
}

// Ranges of the message buffer.
const TAG_RANGE: std::ops::Range<usize> = 0..8;
const SENDER_KEY_RANGE: std::ops::Range<usize> = 8..40;
const SIGNATURE_RANGE: std::ops::Range<usize> = 40..104;
const RECIPIENT_KEY_RANGE: std::ops::Range<usize> = 104..136;
const CONTENT_RANGE: std::ops::RangeFrom<usize> = 136..;
const SIGNED_RANGE: std::ops::RangeFrom<usize> = 104..;

/// The tag of every control message.
pub(crate) const CONTROL_TAG: u64 = 1 << 63;

/// An error representing a failure to parse a control message.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("attempted to parse a control message from too small a buffer")]
    BufferTooSmall,

    #[error("unknown message tag: {0}")]
    Tag(u64),

    #[error("invalid sender public key")]
    SenderKey(#[source] ed25519_dalek::SignatureError),

    #[error("invalid recipient public key")]
    RecipientKey(#[source] ed25519_dalek::SignatureError),

    #[error("failed to deserialize payload")]
    Content(#[source] bincode::Error),
}

/// An error representing a failure to validate a control message.
#[derive(Debug, Error)]
#[error("failed to authenticate control message: {message:?}")]
pub struct AuthenticateError<B: Deref<Target = [u8]>> {
    pub message: Box<Message<B, auth::Invalid>>,

    #[source]
    pub reason: ed25519_dalek::SignatureError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{discriminate, MessageDiscriminant};

    #[test]
    fn serialize_deserialize_payload() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifying_key = signing_key.verifying_key();

        let content = Content::Initiate {
            handshake_timestamp: Duration::ZERO,
            ecdh_public_key: x25519_dalek::PublicKey::from([0; 32]),
            max_heartbeat_interval: Duration::from_secs(60),
        };

        let buffer = Message::new(signing_key, verifying_key, content.clone()).to_buffer();

        let message = Message::deserialize(buffer)
            .expect("failed to deserialize valid message")
            .authenticate()
            .expect("failed to authenticate valid message");

        assert_eq!(message.sender(), &verifying_key);
        assert_eq!(message.recipient(), &verifying_key);
        assert_eq!(*message.content(), content);
    }

    #[test]
    fn deserialize_invalid_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifying_key = signing_key.verifying_key();

        let content = Content::Initiate {
            handshake_timestamp: Duration::ZERO,
            ecdh_public_key: x25519_dalek::PublicKey::from([0; 32]),
            max_heartbeat_interval: Duration::from_secs(60),
        };

        let mut buffer = Message::new(signing_key, verifying_key, content.clone()).to_buffer();

        buffer[SIGNATURE_RANGE][0] ^= 1;

        let message =
            Message::deserialize(buffer).expect("failed to deserialize validly-structured message");

        match message.authenticate() {
            Err(AuthenticateError { message, .. }) => {
                assert_eq!(*message.claimed_sender(), verifying_key);
                assert_eq!(message.claimed_recipient(), &verifying_key);
                assert_eq!(*message.claimed_content(), content);
            }
            Ok(_) => panic!("unexpected success authenticating message"),
        }
    }

    #[test]
    fn discriminate_control() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);

        let content = Content::Initiate {
            handshake_timestamp: Duration::ZERO,
            ecdh_public_key: x25519_dalek::PublicKey::from([0; 32]),
            max_heartbeat_interval: Duration::from_secs(60),
        };

        let buffer =
            Message::new(signing_key.clone(), signing_key.verifying_key(), content).to_buffer();

        assert_eq!(discriminate(buffer).unwrap(), MessageDiscriminant::Control);
    }
}
