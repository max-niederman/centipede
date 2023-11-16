use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
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

    // TODO: add close message
}
