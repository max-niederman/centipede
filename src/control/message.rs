use std::net::SocketAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EndpointId, TunnelId};

pub struct AuthenticatedMessage {
    /// The public key of the sender.
    pub public_key: VerifyingKey,

    /// The message.
    pub message: Message,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Request that the recipient initiate a tunnel.
    CreateTunnel {
        /// The ephemeral public key of the sender.
        ephemeral_key: x25519_dalek::PublicKey,

        /// Tunnel endpoints the sender is listening on.
        endpoints: Vec<Endpoint>,
    },
    /// Acknowledge a tunnel creation request.
    CreateTunnelAcknowledge {
        /// The sender's ID for the tunnel.
        id: TunnelId,

        /// The ephemeral public key of the sender.
        ephemeral_key: x25519_dalek::PublicKey,
    },
    /// Request that the recipient begin sending messages on a tunnel.
    ConnectTunnel {
        /// The ID of the tunnel.
        id: TunnelId,
    },
    /// Request that the recipient destroy a tunnel.
    DestroyTunnel {
        /// The ID of the tunnel.
        id: TunnelId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// The ID of the endpoint.
    pub id: EndpointId,

    /// The address of the endpoint.
    pub address: SocketAddr,
}

impl AuthenticatedMessage {
    /// Parse and verify a binary message.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (public_key, bytes) = bytes.split_array_ref::<{ ed25519_dalek::PUBLIC_KEY_LENGTH }>();
        let (signature, message) = bytes.split_array_ref::<{ ed25519_dalek::SIGNATURE_LENGTH }>();

        let public_key = VerifyingKey::from_bytes(public_key).map_err(Error::InvalidPublicKey)?;
        let signature = Signature::from_bytes(signature);

        public_key
            .verify(message, &signature)
            .map_err(Error::InvalidSignature)?;

        let message = std::str::from_utf8(message)?;
        let message = toml::from_str(message)?;

        Ok(Self {
            public_key,
            message,
        })
    }

    /// Serialize and sign a message.
    pub fn serialize_and_authenticate(
        signing_key: &SigningKey,
        message: &Message,
    ) -> Result<Vec<u8>, Error> {
        let message = toml::to_string(&message)?;
        let message = message.as_bytes();

        let signature = signing_key.sign(message);

        let mut bytes = Vec::with_capacity(
            ed25519_dalek::PUBLIC_KEY_LENGTH + ed25519_dalek::SIGNATURE_LENGTH + message.len(),
        );

        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.extend_from_slice(message);

        Ok(bytes)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid public key")]
    InvalidPublicKey(#[source] ed25519_dalek::SignatureError),

    #[error("invalid signature")]
    InvalidSignature(#[source] ed25519_dalek::SignatureError),

    #[error("invalid message encoding")]
    MessageEncoding(#[from] std::str::Utf8Error),

    #[error("tried to deserialize invalid message")]
    MessageDeserialize(#[from] toml::de::Error),

    #[error("tried to serialize invalid message")]
    MessageSerialize(#[from] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn parse_inverts_serialize() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let message = Message::CreateTunnel {
            ephemeral_key: x25519_dalek::PublicKey::from([0; 32]),
            endpoints: vec![Endpoint {
                id: EndpointId(1.try_into().unwrap()),
                address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            }],
        };

        let bytes =
            AuthenticatedMessage::serialize_and_authenticate(&signing_key, &message).unwrap();
        let authenticated_message = AuthenticatedMessage::parse(&bytes).unwrap();

        assert_eq!(
            authenticated_message.public_key,
            signing_key.verifying_key()
        );
        assert_eq!(authenticated_message.message, message);
    }

    #[test]
    fn parse_catches_invalid_signature() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let message = Message::CreateTunnel {
            ephemeral_key: x25519_dalek::PublicKey::from([0; 32]),
            endpoints: vec![Endpoint {
                id: EndpointId(1.try_into().unwrap()),
                address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)),
            }],
        };

        let mut bytes =
            AuthenticatedMessage::serialize_and_authenticate(&signing_key, &message).unwrap();
        bytes[32] ^= 1;

        assert!(matches!(
            AuthenticatedMessage::parse(&bytes),
            Err(Error::InvalidSignature(_))
        ));
    }
}
