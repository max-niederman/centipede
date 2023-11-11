use std::{mem, net::SocketAddr, rc::Rc};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ed25519_dalek::{SigningKey, VerifyingKey};
use stakker::{actor, call, fail, fwd_to, ret_fail, Actor, ActorOwn, Cx, Share};

use crate::tunnel;

use super::{message::Message, transport};

/// The actor responsible for managing a connection to a peer.
pub struct Connection {
    /// The tunnel state transitioner.
    tunnel_trans: Share<tunnel::StateTransitioner>,

    /// The public key of the peer.
    peer_key: VerifyingKey,

    /// Local addresses to bind tunnel sockets to.
    local_tunnel_addrs: Vec<SocketAddr>,

    /// The message transport to the peer.
    transport: ActorOwn<transport::Peer>,

    /// State of the connection.
    state: State,
}

/// State of the connection.
enum State {
    /// We have accepted a connection but not yet received an `Initiate` message.
    AwaitingInitiate,
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

impl Default for State {
    fn default() -> Self {
        Self::AwaitingInitiate
    }
}

impl Connection {
    /// Create a new connection on the initiating side.
    pub fn initiate(
        cx: &mut Cx<'_, Self>,
        tunnel_trans: Share<tunnel::StateTransitioner>,
        local_tunnel_addrs: Vec<SocketAddr>,
        private_key: Rc<SigningKey>,
        peer_key: VerifyingKey,
        peer_addr: SocketAddr,
    ) -> Option<Self> {
        let ecdh_private_key =
            x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::thread_rng());

        let transport = actor!(
            cx,
            <transport::Peer>::initiate(
                private_key,
                peer_key,
                peer_addr,
                fwd_to!([cx], handle_inbound_message() as (Message))
            ),
            ret_fail!(cx, "failed to create peer")
        );

        call!(
            [transport],
            send(Message::Initiate {
                ecdh_public_key: x25519_dalek::PublicKey::from(&ecdh_private_key),
            })
        );

        Some(Self {
            tunnel_trans,
            local_tunnel_addrs,
            peer_key,
            transport,
            state: State::AwaitingInitiateAck { ecdh_private_key },
        })
    }

    /// Accept a new connection on the responding side.
    pub fn accept(
        cx: &mut Cx<'_, Self>,
        tunnel_trans: Share<tunnel::StateTransitioner>,
        local_tunnel_addrs: Vec<SocketAddr>,
        transport: transport::AcceptedPeer,
    ) -> Option<Self> {
        let peer_key = transport.public_key();

        let transport = actor!(
            cx,
            <transport::Peer>::from_accepted(
                transport,
                fwd_to!([cx], handle_inbound_message() as (Message))
            ),
            ret_fail!(cx, "failed to create peer")
        );

        Some(Self {
            tunnel_trans,
            local_tunnel_addrs,
            peer_key,
            transport,
            state: State::AwaitingInitiate,
        })
    }

    pub fn update_local_tunnel_addrs(&mut self, cx: &mut Cx<'_, Self>, addrs: Vec<SocketAddr>) {
        self.local_tunnel_addrs = addrs;

        call!(
            [self.transport],
            send(Message::UpdateAddresses {
                addresses: self.local_tunnel_addrs.clone(),
            })
        );
    }

    /// Handle an inbound control message.
    fn handle_inbound_message(&mut self, cx: &mut Cx<'_, Self>, message: Message) {
        self.state = match (mem::take(&mut self.state), message) {
            (State::AwaitingInitiate, Message::Initiate { ecdh_public_key }) => {
                let ecdh_private_key =
                    x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::thread_rng());

                call!(
                    [self.transport],
                    send(Message::InitiateAck {
                        ecdh_public_key: x25519_dalek::PublicKey::from(&ecdh_private_key),
                        responder_addresses: todo!(),
                    })
                );

                let ecdh_shared_secret = ecdh_private_key.diffie_hellman(&ecdh_public_key);

                self.upsert_receive_tunnel(cx, ecdh_shared_secret);

                State::InboundEstablished { ecdh_shared_secret }
            }

            (
                State::AwaitingInitiateAck { ecdh_private_key },
                Message::InitiateAck {
                    ecdh_public_key,
                    responder_addresses,
                },
            ) => {
                call!(
                    [self.transport],
                    send(Message::UpdateAddresses {
                        addresses: self.local_tunnel_addrs.clone()
                    })
                );

                let ecdh_shared_secret = ecdh_private_key.diffie_hellman(&ecdh_public_key);

                self.upsert_receive_tunnel(cx, ecdh_shared_secret);

                State::InboundEstablished { ecdh_shared_secret }
            }

            (
                State::InboundEstablished { ecdh_shared_secret },
                Message::UpdateAddresses { addresses },
            ) => {
                self.upsert_send_tunnel(cx, ecdh_shared_secret, addresses);

                State::InboundEstablished { ecdh_shared_secret }
            }

            (old_state, message) => {
                fail!(
                    cx,
                    "received unexpected message for state: {message:#?} for {state:#?}"
                );
                old_state
            }
        }
    }

    fn upsert_receive_tunnel(
        &mut self,
        cx: &mut Cx<'_, Self>,
        ecdh_shared_secret: x25519_dalek::SharedSecret,
    ) {
        let (&peer_id, _) = self.peer_key.to_bytes().split_array_ref::<8>();
        self.tunnel_trans.rw(cx).upsert_receive_tunnel(
            peer_id,
            ChaCha20Poly1305::new(ecdh_shared_secret.as_bytes().into()),
        );
    }

    fn upsert_send_tunnel(
        &mut self,
        cx: &mut Cx<'_, Self>,
        ecdh_shared_secret: x25519_dalek::SharedSecret,
        remote_addrs: Vec<SocketAddr>,
    ) {
        let (&peer_id, _) = self.peer_key.to_bytes().split_array_ref::<8>();
        self.tunnel_trans.rw(cx).upsert_send_tunnel(
            peer_id,
            ChaCha20Poly1305::new(ecdh_shared_secret.as_bytes().into()),
            self.local_tunnel_addrs.clone(),
            remote_addrs,
        );
    }
}
