use ed25519_dalek::{SigningKey, VerifyingKey};
use stakker::{Actor, Cx};

use super::{message::Message, tunnels::Tunnels};

/// The actor responsible for managing a connection to a peer.
pub struct Connection {
    /// A handle to the tunnels actor.
    tunnels: Actor<Tunnels>,

    /// The key pair of the local machine.
    local_key: SigningKey,

    /// The public key of the peer.
    peer_public_key: VerifyingKey,

    /// State of the connection.
    state: State,
}

/// State of the connection.
enum State {
    /// We have sent an `Initiate` message and are awaiting an `InitiateAck` response.
    AwaitingInitiateAck {
        /// Our ephemeral Diffie-Hellman private key.
        ecdh_private_key: x25519_dalek::EphemeralSecret,
    },
    /// At least the inbound half of the connection is established.
    ///
    /// Usually this refers to the fully established connection,
    /// but this also covers the case where the responder has sent an `InitiateAck`
    /// but is still waiting for an `UpdateAddresses` message from the initiator to begin sending
    InboundEstablished {
        /// The ephemeral Diffie-Hellman shared secret.
        ecdh_shared_secret: x25519_dalek::SharedSecret,
    },
}

impl Connection {
    /// Create a new connection on the initiating side.
    pub fn initiate(
        _cx: &mut Cx<'_, Self>,
        tunnels: Actor<Tunnels>,
        local_key: SigningKey,
        peer_public_key: VerifyingKey,
    ) -> Self {
        let ecdh_private_key =
            x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::thread_rng());

        Self {
            tunnels,
            local_key,
            peer_public_key,
            state: State::AwaitingInitiateAck { ecdh_private_key },
        }
    }

    /// Handle an inbound control message.
    fn handle_inbound_message(&mut self, _cx: &mut Cx<'_, Self>, message: Message) {
        todo!()
    }
}
