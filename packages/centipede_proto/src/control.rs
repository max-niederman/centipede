use std::{fmt::Debug, marker::PhantomData, net::SocketAddr};

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth;

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

    /// The sequence number of the message.
    sequence_number: u64,

    /// The content of the message
    content: MessageKind,

    /// Marker for the authentication status.
    _auth: PhantomData<A>,
}

/// The kind of a control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    /// A payload.
    Payload(Payload),

    /// An acknowledgement.
    Ack,
}

/// The payload of a control message.
/// Carries the actual content without authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// Initiate a connection.
    ///
    /// Sent by the initiator to the responder.
    Initiate {
        /// The ephemeral Diffie-Hellman public key of the sender.
        /// This is used to derive the shared secret.
        ecdh_public_key: x25519_dalek::PublicKey,
    },

    /// Acknowledge a connection initiation.
    ///
    /// Sent by the responder to the initiator.
    InitiateAck {
        /// The ephemeral Diffie-Hellman public key of the sender.
        /// This is used to derive the shared secret.
        ecdh_public_key: x25519_dalek::PublicKey,

        /// Socket addresses on which the responder is listening.
        responder_addresses: Vec<SocketAddr>,
    },

    /// Update the addresses of the sender on the receiver.
    ///
    /// Sent by either peer to the other.
    /// In particular, sent by the initiator to the responder after receiving an `InitiateAck`.
    UpdateAddresses {
        /// Socket addresses on which the sender is listening.
        addresses: Vec<SocketAddr>,
    },
}

impl<A: auth::Status> Message<A> {
    /// The claimed sender public key of this message.
    pub fn claimed_sender(&self) -> &ed25519_dalek::VerifyingKey {
        &self.sender
    }

    /// The claimed sequence number of this message.
    pub fn claimed_sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// The claimed content of this message.
    pub fn claimed_content(&self) -> &MessageKind {
        &self.content
    }
}

impl Message<auth::Valid> {
    /// The validated sender public key of this message.
    pub fn sender(&self) -> &ed25519_dalek::VerifyingKey {
        self.claimed_sender()
    }

    /// The validated sequence number of this message.
    pub fn sequence_number(&self) -> u64 {
        self.claimed_sequence_number()
    }

    /// The validated content of this message.
    pub fn content(&self) -> &MessageKind {
        self.claimed_content()
    }

    /// Create a new control message.
    pub fn serialize(
        signing_key: &ed25519_dalek::SigningKey,
        sequence_number: u64,
        content: MessageKind,
    ) -> Vec<u8> {
        let size = PAYLOAD_RANGE.start
            + match &content {
                MessageKind::Payload(payload) => bincode::serialized_size(payload).unwrap_or(0),
                MessageKind::Ack => 0,
            } as usize;

        let mut buffer = vec![0; size];

        buffer[SENDER_KEY_RANGE].copy_from_slice(signing_key.verifying_key().as_bytes());

        buffer[SEQUENCE_NUMBER_RANGE].copy_from_slice(&sequence_number.to_be_bytes());

        match content {
            MessageKind::Payload(payload) => {
                buffer[KIND_RANGE].copy_from_slice(&KIND_PAYLOAD.to_be_bytes());
                bincode::serialize_into(&mut buffer[PAYLOAD_RANGE], &payload).unwrap();
            }
            MessageKind::Ack => {
                buffer[KIND_RANGE].copy_from_slice(&KIND_ACK.to_be_bytes());
            }
        }

        let signature = signing_key.sign(&buffer[SIGNED_RANGE]);
        buffer[SIGNATURE_RANGE].copy_from_slice(&signature.to_bytes());

        buffer
    }

    /// Parse and validate a control message.
    pub fn parse_and_validate(buffer: &[u8]) -> Result<Self, ParseValidateError> {
        if buffer.len() < PAYLOAD_RANGE.start {
            return Err(ParseError::BufferTooSmall.into());
        }

        let sender =
            ed25519_dalek::VerifyingKey::from_bytes(&buffer[SENDER_KEY_RANGE].try_into().unwrap())
                .map_err(ParseError::PublicKey)?;

        let signature =
            ed25519_dalek::Signature::from_bytes(&buffer[SIGNATURE_RANGE].try_into().unwrap());

        let sequence_number = u64::from_be_bytes(buffer[SEQUENCE_NUMBER_RANGE].try_into().unwrap());

        let kind = u32::from_be_bytes(buffer[KIND_RANGE].try_into().unwrap());

        let content = match kind {
            KIND_PAYLOAD => {
                let payload = bincode::deserialize(&buffer[PAYLOAD_RANGE])
                    .map_err(ParseError::Deserialize)?;

                MessageKind::Payload(payload)
            }
            KIND_ACK => MessageKind::Ack,
            _ => return Err(ParseError::InvalidKind(kind).into()),
        };

        match sender.verify_strict(&buffer[SIGNED_RANGE], &signature) {
            Ok(_) => Ok(Message {
                sender,
                signature,
                sequence_number,
                content,
                _auth: PhantomData::<auth::Valid>,
            }),
            Err(e) => Err(ValidateError {
                message: Message {
                    sender,
                    signature,
                    sequence_number,
                    content,
                    _auth: PhantomData::<auth::Invalid>,
                },
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
            .field("sequence_number", &self.sequence_number)
            .field("content", &self.content)
            .field("_auth", &A::NAME)
            .finish()
    }
}

// Ranges of the message buffer.
const SENDER_KEY_RANGE: std::ops::Range<usize> = 0..32;
const SIGNATURE_RANGE: std::ops::Range<usize> = 32..96;
const SEQUENCE_NUMBER_RANGE: std::ops::Range<usize> = 96..104;
const KIND_RANGE: std::ops::Range<usize> = 104..108;
const PAYLOAD_RANGE: std::ops::RangeFrom<usize> = 108..;
const SIGNED_RANGE: std::ops::RangeFrom<usize> = 96..;

// Kinds of control messages.
const KIND_PAYLOAD: u32 = 0;
const KIND_ACK: u32 = 1;

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
    pub message: Message<auth::Invalid>,

    #[source]
    pub reason: ed25519_dalek::SignatureError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_payload() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifying_key = signing_key.verifying_key();

        let sequence_number = 42;
        let payload = Payload::Initiate {
            ecdh_public_key: x25519_dalek::PublicKey::from([0; 32]),
        };

        let buffer = Message::<auth::Valid>::serialize(
            &signing_key,
            sequence_number,
            MessageKind::Payload(payload.clone()),
        );

        let message = Message::<auth::Valid>::parse_and_validate(&buffer).unwrap();

        assert_eq!(message.sender(), &verifying_key);
        assert_eq!(message.sequence_number(), sequence_number);
        assert_eq!(*message.content(), MessageKind::Payload(payload));
    }

    #[test]
    fn serialize_deserialize_ack() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifying_key = signing_key.verifying_key();

        let sequence_number = 43;

        let buffer =
            Message::<auth::Valid>::serialize(&signing_key, sequence_number, MessageKind::Ack);

        let message = Message::<auth::Valid>::parse_and_validate(&buffer).unwrap();

        assert_eq!(message.sender(), &verifying_key);
        assert_eq!(message.sequence_number(), sequence_number);
        assert_eq!(*message.content(), MessageKind::Ack);
    }

    #[test]
    fn deserialize_invalid_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let verifying_key = signing_key.verifying_key();

        let sequence_number = 44;
        let payload = Payload::Initiate {
            ecdh_public_key: x25519_dalek::PublicKey::from([0; 32]),
        };

        let mut buffer = Message::<auth::Valid>::serialize(
            &signing_key,
            sequence_number,
            MessageKind::Payload(payload.clone()),
        );

        buffer[SIGNATURE_RANGE][0] ^= 1;

        match Message::<auth::Valid>::parse_and_validate(&buffer) {
            Err(ParseValidateError::Validate(ValidateError { message, .. })) => {
                assert_eq!(*message.claimed_sender(), verifying_key);
                assert_eq!(message.claimed_sequence_number(), sequence_number);
                assert_eq!(*message.claimed_content(), MessageKind::Payload(payload));
            }
            Err(e) => panic!("unexpected error: {}", e),
            Ok(_) => panic!("unexpected success"),
        }
    }
}
