use std::{fmt::Debug, marker::PhantomData, net::SocketAddr, ops::Deref, time::Duration};

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::marker::auth;

/// A parsed control message used to establish and maintain a connection.
#[derive(Clone, PartialEq, Eq)]
pub struct Message<A>
where
    A: auth::Status,
{
    /// The sender's claimed public key.
    sender: ed25519_dalek::VerifyingKey,

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

impl<A: auth::Status> Message<A> {
    /// The claimed sender public key of this message.
    pub fn claimed_sender(&self) -> &ed25519_dalek::VerifyingKey {
        &self.sender
    }

    /// The claimed content of this message.
    pub fn claimed_content(&self) -> &Content {
        &self.content
    }
}

impl Message<auth::Valid> {
    /// The validated sender public key of this message.
    pub fn sender(&self) -> &ed25519_dalek::VerifyingKey {
        self.claimed_sender()
    }

    /// The validated content of this message.
    pub fn content(&self) -> &Content {
        self.claimed_content()
    }

    /// Create a new control message.
    pub fn new(signing_key: &ed25519_dalek::SigningKey, content: Content) -> Self {
        Message {
            sender: signing_key.verifying_key(),
            signature: signing_key.sign(&bincode::serialize(&content).unwrap()),
            content,
            _auth: PhantomData::<auth::Valid>,
        }
    }

    /// Serialize a control message to a buffer.
    pub fn serialize(&self) -> Vec<u8> {
        let size =
            CONTENT_RANGE.start + bincode::serialized_size(&self.content).unwrap_or(0) as usize;

        let mut buffer = vec![0; size];

        buffer[TAG_RANGE].copy_from_slice(&CONTROL_TAG.to_be_bytes());

        buffer[SENDER_KEY_RANGE].copy_from_slice(self.sender.as_bytes());

        bincode::serialize_into(&mut buffer[CONTENT_RANGE], &self.content).unwrap();

        buffer[SIGNATURE_RANGE].copy_from_slice(&self.signature.to_bytes());

        buffer
    }

    /// Parse and validate a control message.
    pub fn parse_and_validate(buffer: &[u8]) -> Result<Self, ParseValidateError> {
        let sender =
            ed25519_dalek::VerifyingKey::from_bytes(&buffer[SENDER_KEY_RANGE].try_into().unwrap())
                .map_err(ParseError::PublicKey)?;

        let signature =
            ed25519_dalek::Signature::from_bytes(&buffer[SIGNATURE_RANGE].try_into().unwrap());

        let payload =
            bincode::deserialize(&buffer[CONTENT_RANGE]).map_err(ParseError::Deserialize)?;

        match sender.verify_strict(&buffer[SIGNED_RANGE], &signature) {
            Ok(_) => Ok(Message {
                sender,
                signature,
                content: payload,
                _auth: PhantomData::<auth::Valid>,
            }),
            Err(e) => Err(ValidateError {
                message: Box::new(Message {
                    sender,
                    signature,
                    content: payload,
                    _auth: PhantomData::<auth::Invalid>,
                }),
                reason: e,
            }
            .into()),
        }
    }
}

impl<A: auth::Status> Debug for Message<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("sender", &self.sender)
            .field("signature", &self.signature)
            .field("content", &self.content)
            .field("_auth", &A::NAME)
            .finish()
    }
}

/// A buffer to be deserialized and validated lazily.
pub struct LazyMessage<B>
where
    B: Deref<Target = [u8]>,
{
    /// The buffer to be deserialized and validated.
    buffer: B,
}

impl<B> LazyMessage<B>
where
    B: Deref<Target = [u8]>,
{
    /// Create a new lazy message from a buffer.
    pub fn from_buffer(buffer: B) -> Self {
        Self { buffer }
    }

    /// Deserialize and validate the message.
    pub fn realize(self) -> Result<Message<auth::Valid>, ParseValidateError> {
        Message::parse_and_validate(&self.buffer)
    }
}

// Ranges of the message buffer.
const TAG_RANGE: std::ops::Range<usize> = 0..8;
const SENDER_KEY_RANGE: std::ops::Range<usize> = 8..40;
const SIGNATURE_RANGE: std::ops::Range<usize> = 40..104;
const CONTENT_RANGE: std::ops::RangeFrom<usize> = 104..;
const SIGNED_RANGE: std::ops::RangeFrom<usize> = CONTENT_RANGE;

/// The tag of every control message.
pub(crate) const CONTROL_TAG: u64 = 1 << 63;

/// An error representing a failure to parse or validate a control message.
#[derive(Debug, Error)]
pub enum ParseValidateError {
    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Validate(#[from] ValidateError),
}

/// An error representing a failure to parse a control message.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("attempted to parse a control message from too small a buffer")]
    BufferTooSmall,

    #[error("invalid public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),

    #[error("invalid kind of control message with tag {0}")]
    InvalidKind(u32),

    #[error("failed to deserialize payload")]
    Deserialize(#[source] bincode::Error),
}

/// An error representing a failure to validate a control message.
#[derive(Debug, Error)]
#[error("failed to validate control message: {message:?}")]
pub struct ValidateError {
    pub message: Box<Message<auth::Invalid>>,

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

        let buffer = Message::new(&signing_key, content.clone()).serialize();

        let message = Message::<auth::Valid>::parse_and_validate(&buffer).unwrap();

        assert_eq!(message.sender(), &verifying_key);
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

        let mut buffer = Message::new(&signing_key, content.clone()).serialize();

        buffer[SIGNATURE_RANGE][0] ^= 1;

        match Message::<auth::Valid>::parse_and_validate(&buffer) {
            Err(ParseValidateError::Validate(ValidateError { message, .. })) => {
                assert_eq!(*message.claimed_sender(), verifying_key);
                assert_eq!(*message.claimed_content(), content);
            }
            Err(e) => panic!("unexpected error: {}", e),
            Ok(_) => panic!("unexpected success"),
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

        let buffer = Message::new(&signing_key, content).serialize();

        assert_eq!(discriminate(buffer).unwrap(), MessageDiscriminant::Control);
    }
}
