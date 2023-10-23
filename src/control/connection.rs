use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use stakker::{Actor, Cx};

use crate::tunnel;

use super::tunnels::Tunnels;

/// The actor responsible for managing a connection to a peer.
pub struct Connection {
    /// A handle to the tunnels actor.
    tunnels: Actor<Tunnels>,

    /// The key pair of the local machine.
    local_key: SigningKey,

    /// The public key of the peer.
    peer_public_key: VerifyingKey,

    /// Known remote (outbound) generations.
    remote_generations: BTreeMap<u64, (x25519_dalek::SharedSecret, Vec<tunnel::Endpoint>)>,

    /// State of the inbound half of the connection.
    inbound_state: InboundState,
}

enum InboundState {
    AwaitingFirstAck {
        local_dh_public_key: x25519_dalek::PublicKey,
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
        Self {
            tunnels,
            local_key,
            peer_public_key,
            local_generation: 0,
            remote_generations: BTreeMap::new(),
            state: State::Disconnected,
        }
    }
}
