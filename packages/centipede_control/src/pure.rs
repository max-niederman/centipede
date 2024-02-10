//! Pure state machine implementation of the Centipede control protocol.
//!
//! Performs no I/O, and is intended to be used as a building block for a real control daemon.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    task::Poll,
    time::SystemTime,
};

use centipede_proto::{control::Message, marker::auth};
use chacha20poly1305::ChaCha20Poly1305;

/// A Centipede control daemon, implemented as a pure state machine.
pub struct Controller {
    /// Peer state, by public key.
    peers: HashMap<ed25519_dalek::VerifyingKey, PeerState>,

    /// Actions to be taken at some point in the future.
    timers: BTreeMap<SystemTime, TimerAction>,
}

/// The state of the controller w.r.t. a peer.
enum PeerState {}

/// An action to be taken when a timer expires.
enum TimerAction {}

impl Controller {
    /// Create a new, empty controller.
    pub fn new(now: SystemTime) -> Self {
        todo!()
    }

    /// Register a new peer and start listening for incoming connections.
    pub fn listen(&mut self, now: SystemTime, public_key: ed25519_dalek::VerifyingKey) {
        todo!()
    }

    /// Initiate a connection to a peer. Must be called after `listen`.
    pub fn initiate(
        &mut self,
        now: SystemTime,
        public_key: ed25519_dalek::VerifyingKey,
        known_addrs: Vec<SocketAddr>,
    ) {
        todo!()
    }

    /// Disconnect from a peer.
    pub fn disconnect(&mut self, now: SystemTime, public_key: ed25519_dalek::VerifyingKey) {
        todo!()
    }

    /// Handle an incoming message, transitioning the state machine.
    pub fn handle_incoming(&mut self, now: SystemTime, message: Message<auth::Valid>) {
        todo!()
    }

    /// Poll for outgoing messages.
    pub fn poll_outgoing(&mut self, now: SystemTime) -> Poll<Message<auth::Valid>> {
        todo!()
    }

    /// Poll for new router configurations.
    pub fn poll_router_config(&mut self, now: SystemTime) -> Poll<centipede_router::Config> {
        todo!()
    }
}
