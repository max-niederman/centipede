use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    rc::Rc,
    time::Duration,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use stakker::{actor, after, call, fail, fwd_to, lazy, ret_fail, ActorOwn, Cx, Fwd};

use envelope::{AuthenticatedEnvelope, Envelope, SignedEnvelope};

use super::message::Message;

mod envelope;
mod udp;

/// An actor accepting connections from peers.
pub struct Acceptor {
    /// The underlying UDP acceptor.
    udp_acceptor: ActorOwn<udp::Acceptor>,

    /// Our private key.
    private_key: Rc<SigningKey>,

    /// Peer receiver.
    receiver: Fwd<AcceptedPeer>,
}

impl Acceptor {
    pub fn new(
        cx: &mut Cx<'_, Self>,
        private_key: Rc<SigningKey>,
        local_addr: SocketAddr,
        receiver: Fwd<AcceptedPeer>,
    ) -> Option<Self> {
        let udp_acceptor = actor!(
            cx,
            <udp::Acceptor>::new(local_addr, fwd_to!([cx], accept() as (udp::AcceptedSocket)),),
            ret_fail!(cx, "failed to create UDP acceptor")
        );

        Some(Self {
            udp_acceptor,
            private_key,
            receiver,
        })
    }

    fn accept(&mut self, cx: &mut Cx<'_, Self>, socket: udp::AcceptedSocket) {
        let envelope = match SignedEnvelope::deserialize(socket.peek()) {
            Ok(envelope) => envelope,
            Err(e) => {
                log::warn!("failed to deserialize first signed envelope: {}", e);
                return;
            }
        };

        self.receiver.fwd(AcceptedPeer {
            socket,
            private_key: self.private_key.clone(),
            peer_key: envelope.claimed_sender(),
        })
    }
}

/// A peer which has been accepted by the acceptor.
pub struct AcceptedPeer {
    /// The underlying UDP socket.
    socket: udp::AcceptedSocket,

    /// Our private key.
    private_key: Rc<SigningKey>,

    /// The public key of the peer.
    peer_key: VerifyingKey,
}

impl AcceptedPeer {
    pub fn public_key(&self) -> VerifyingKey {
        self.peer_key
    }
}

/// An actor representing a peer.
pub struct Peer {
    /// The underlying UDP socket.
    socket: ActorOwn<udp::Socket>,

    /// Our private key.
    private_key: Rc<SigningKey>,

    /// The public key of the peer.
    peer_key: VerifyingKey,

    /// The next sequence number to use for outbound messages.
    next_outbound: u64,

    /// Outstanding outbound messages.
    outstanding_outbound: HashMap<u64, SignedEnvelope>,

    /// A set of received inbound messages.
    received_inbound: BTreeSet<u64>,

    /// Receiver for inbound messages.
    receiver: Fwd<Message>,
}

/// The number of sequence numbers to remember.
///
/// Should be one less than a power of two.
const SEQUENCE_MEMORY: usize = 255;

impl Peer {
    /// Create a new peer from an accepted socket.
    pub fn from_accepted(
        cx: &mut Cx<'_, Self>,
        accepted: AcceptedPeer,
        receiver: Fwd<Message>,
    ) -> Option<Self> {
        let socket = actor!(
            cx,
            <udp::Socket>::from_accepted(accepted.socket, fwd_to!([cx], receive() as (Vec<u8>))),
            ret_fail!(cx, "failed to create underlying UDP socket")
        );

        Some(Self {
            socket,
            private_key: accepted.private_key,
            peer_key: accepted.peer_key,
            next_outbound: 0,
            outstanding_outbound: HashMap::new(),
            received_inbound: BTreeSet::new(),
            receiver,
        })
    }

    /// Initiate a connection to a peer.
    pub fn initiate(
        cx: &mut Cx<'_, Self>,
        private_key: Rc<SigningKey>,
        peer_key: VerifyingKey,
        peer_addr: SocketAddr,
        receiver: Fwd<Message>,
    ) -> Option<Self> {
        let socket = actor!(
            cx,
            <udp::Socket>::connect(peer_addr, fwd_to!([cx], receive() as (Vec<u8>)),),
            ret_fail!(cx, "failed to connect UDP socket")
        );

        Some(Peer {
            socket,
            private_key,
            peer_key,
            next_outbound: 0,
            outstanding_outbound: HashMap::new(),
            received_inbound: BTreeSet::new(),
            receiver,
        })
    }

    fn receive(&mut self, cx: &mut Cx<'_, Self>, datagram: Vec<u8>) {
        let envelope = match SignedEnvelope::deserialize(&datagram) {
            Ok(envelope) => envelope,
            Err(e) => {
                log::warn!("failed to deserialize envelope: {}", e);
                return;
            }
        };

        let envelope = match envelope.verify() {
            Ok(AuthenticatedEnvelope { sender, envelope }) if sender == self.peer_key => envelope,
            Ok(_) => {
                log::warn!("received message from invalid sender");
                return;
            }
            Err(e) => {
                log::warn!("failed to verify envelope: {}", e);
                return;
            }
        };

        match envelope {
            Envelope::Message { sequence, message } => {
                let acknowledgement = Envelope::Acknowledgement { sequence }
                    .sign(&self.private_key)
                    .expect("failed to sign acknowledgement");

                // TODO: should this be `idle`?
                lazy!([self.socket, cx], send(acknowledgement.serialize()));

                if self.received_inbound.insert(sequence) {
                    self.receiver.fwd(message);

                    if self.received_inbound.len() > SEQUENCE_MEMORY {
                        self.received_inbound.pop_first();
                    }
                } else {
                    log::warn!("received duplicate message");
                }
            }
            Envelope::Acknowledgement { sequence } => {
                self.outstanding_outbound.remove(&sequence);
            }
        }
    }

    /// Send a message to the peer.
    pub fn send(&mut self, cx: &mut Cx<'_, Self>, message: Message) {
        let sequence = self.next_outbound;
        self.next_outbound += 1;

        let envelope = Envelope::Message { sequence, message }.sign(&self.private_key);
        let envelope = match envelope {
            Ok(envelope) => envelope,
            Err(e) => {
                fail!(cx, "failed to sign message: {}", e);
                return;
            }
        };

        assert!(
            self.outstanding_outbound
                .insert(sequence, envelope)
                .is_none(),
            "sequence number {} already in use",
            sequence
        );

        call!([cx], ensure_delivery(sequence, Duration::from_millis(250)));
    }

    fn ensure_delivery(&mut self, cx: &mut Cx<'_, Self>, sequence: u64, timeout: Duration) {
        if let Some(envelope) = self.outstanding_outbound.get(&sequence) {
            call!([self.socket], send(envelope.serialize()));
            after!(timeout, [cx], ensure_delivery(sequence, timeout * 2));
        }
    }
}
