//! The control plane.
//!
//! # I/O Priority Levels:
//! 0. Listener sockets
//! 1. Connected sockets
//!
//! This prevents a DoS attack on the listener from blocking connected
//! sockets from receiving messages.

use std::{collections::HashMap, net::SocketAddr, rc::Rc};

use ed25519_dalek::{SigningKey, VerifyingKey};
use replace_with::replace_with_or_abort;
use serde::{Deserialize, Serialize};
use stakker::{actor, call, fwd_to, ret_fail, ret_panic, ActorOwn, Cx, Share};

use crate::tunnel;

use self::connection::Connection;

pub mod message;

mod connection;
pub mod daemon;
mod transport;

/// The specification of the target state of the controller.
///
/// It is the controller's job to drive the system to this state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spec {
    /// Private key of the daemon.
    pub private_key: SigningKey,

    /// Local Internet address to bind the control socket to.
    pub local_control_address: SocketAddr,

    /// Desired peer connections.
    pub peers: HashMap<VerifyingKey, ConnectionSpec>,
}

/// The specification of a connection to a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionSpec {
    /// Local Internet addresses to bind tunnel sockets to.
    pub local_tunnel_addresses: Vec<SocketAddr>,

    /// Remote Internet address of the peer's control socket.
    /// If `None`, we can only accept connections from the peer.
    pub remote_control_address: Option<SocketAddr>,
}

/// The controller.
pub struct Controller {
    /// The tunnel state transitioner.
    tunnel_trans: Share<tunnel::StateTransitioner>,

    /// Our private key.
    private_key: Rc<SigningKey>,

    /// Acceptor for incoming connections.
    acceptor: ActorOwn<transport::Acceptor>,

    /// Peer states.
    peers: HashMap<VerifyingKey, PeerState>,
}

enum PeerState {
    /// We are listening for incoming connections from the peer.
    Listening {
        /// Addresses to use for the tunnel when we accept a connection.
        local_tunnel_addresses: Vec<SocketAddr>,
    },
    /// We have initiated a connection to the peer.
    Initiated(ActorOwn<Connection>),
}

impl Controller {
    /// Create a new controller.
    pub fn new(
        cx: &mut Cx<'_, Self>,
        tunnel_trans: Share<tunnel::StateTransitioner>,
        init_spec: Spec,
    ) -> Option<Self> {
        let private_key = Rc::new(init_spec.private_key);

        let acceptor = actor!(
            cx,
            <transport::Acceptor>::new(
                private_key.clone(),
                init_spec.local_control_address,
                fwd_to!([cx], accept() as (transport::AcceptedPeer))
            ),
            ret_fail!(cx, "transport acceptor failed")
        );

        let mut this = Self {
            tunnel_trans,
            private_key,
            acceptor,
            peers: HashMap::new(),
        };

        for (key, spec) in init_spec.peers {
            this.peers.insert(key, this.new_peer(&mut *cx, key, spec));
        }

        Some(this)
    }

    fn accept(&mut self, cx: &mut Cx<'_, Self>, transport: transport::AcceptedPeer) {
        let peer_key = transport.public_key();

        if let Some(peer_state) = self.peers.get_mut(&peer_key) {
            log::info!("got connection from known peer {:?}", peer_key);

            replace_with_or_abort(peer_state, |peer_state| match peer_state {
                PeerState::Listening {
                    local_tunnel_addresses,
                } => {
                    let connection = actor!(
                        cx,
                        Connection::accept(
                            self.tunnel_trans.clone(),
                            local_tunnel_addresses,
                            transport,
                        ),
                        ret_panic!("todo: handle connection failure")
                    );

                    PeerState::Initiated(connection)
                }
                PeerState::Initiated(connection) => {
                    log::info!(
                        "got connection from peer {:?} while already connected",
                        peer_key
                    );

                    call!([connection], reaccept(transport));

                    PeerState::Initiated(connection)
                }
            })
        } else {
            log::warn!("got connection from unknown peer {:?}", peer_key);
        }
    }

    /// Update the specification.
    pub fn update_spec(&mut self, cx: &mut Cx<'_, Self>, spec: Spec) {
        self.peers = spec
            .peers
            .into_iter()
            .map(|(key, spec)| match self.peers.remove(&key) {
                Some(PeerState::Initiated(conn)) => {
                    call!(
                        [conn],
                        update_local_tunnel_addrs(spec.local_tunnel_addresses)
                    );

                    (key, PeerState::Initiated(conn))
                }
                _ => (key, self.new_peer(cx, key, spec)),
            })
            .collect();
    }

    /// Utility function to create a new peer state from a specification.
    fn new_peer(
        &self,
        core: &mut stakker::Core,
        key: VerifyingKey,
        spec: ConnectionSpec,
    ) -> PeerState {
        if let Some(remote_control_addr) = spec.remote_control_address {
            PeerState::Initiated(actor!(
                core,
                Connection::initiate(
                    self.tunnel_trans.clone(),
                    spec.local_tunnel_addresses,
                    self.private_key.clone(),
                    key,
                    remote_control_addr
                ),
                ret_panic!("todo: handle connection failure")
            ))
        } else {
            PeerState::Listening {
                local_tunnel_addresses: spec.local_tunnel_addresses,
            }
        }
    }
}
