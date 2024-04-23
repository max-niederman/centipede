use std::{
    collections::{HashMap, HashSet},
    io,
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, SystemTime},
};

use centipede_proto::{
    marker::{auth, text},
    PacketMessage,
};
use centipede_router::{
    config::{self, ConfiguratorHandle},
    worker::{SendPacket, WorkerHandle},
    Link, PeerId, Router,
};

mod common;
use common::*;

/// Test a network with zero peers.
///
/// Primarily a meta-test on the test harness.
#[test]
fn empty_network() {
    PeerCtx::run(vec![]);
}

/// Test a network with one peer.
///
/// Primarily a meta-test on the test harness.
#[test]
fn single_peer() {
    PeerCtx::run(vec![PeerSpec {
        id: [0; 8],
        addr_count: 1,
        entrypoint: Box::new(|mut ctx: PeerCtx<'_>| {
            let mut obligations = ctx.worker.handle_outgoing(&[0; 1024]);
            assert!(
                obligations.resume(vec![]).is_none(),
                "router is alone, but attempted to send a packet"
            );
        }),
    }]);
}

/// Send a single message over a half-duplex connection.
#[test]
fn half_duplex_single_message() {
    const PACKET: &[u8] = "Hello, centipede!".as_bytes();

    PeerCtx::run(vec![
        PeerSpec {
            id: [0; 8],
            addr_count: 1,
            entrypoint: Box::new(|mut ctx: PeerCtx<'_>| {
                ctx.configurator.configure(&config::Router {
                    send_tunnels: {
                        let mut map = HashMap::new();
                        map.insert(
                            [1; 8],
                            config::SendTunnel {
                                initialized_at: SystemTime::UNIX_EPOCH,
                                cipher: dummy_cipher(),
                                links: ctx.possible_links_to([1; 8]),
                            },
                        );
                        map
                    },
                    ..ctx.init_config.clone()
                });

                let mut obligations = ctx.worker.handle_outgoing(PACKET);
                let mut scratch = Vec::new();

                scratch = match obligations.resume(scratch) {
                    Some(obligation) => {
                        assert_eq!(obligation.message().sequence_number(), 0);
                        assert_eq!(obligation.message().sender(), [0; 8]);

                        ctx.fulfill_send(obligation)
                    }
                    None => panic!("sending router did not attempt to send a packet"),
                };

                assert!(
                    obligations.resume(scratch).is_none(),
                    "sending router attempted to send a second packet when only one link was configured"
                );
            }),
        },
        PeerSpec {
            id: [1; 8],
            addr_count: 1,
            entrypoint: Box::new(|mut ctx: PeerCtx<'_>| {
                ctx.configurator.configure(&config::Router {
                    recv_tunnels: {
                        let mut map = HashMap::new();
                        map.insert(
                            [0; 8],
                            config::RecvTunnel {
                                initialized_at: SystemTime::UNIX_EPOCH,
                                cipher: dummy_cipher(),
                            },
                        );
                        map
                    },
                    ..ctx.init_config.clone()
                });

                let packets = ctx.receive_block();
                assert_eq!(packets.len(), 1, "received wrong number of packets");
                let packet = packets.into_iter().next().unwrap();

                match ctx.worker.handle_incoming(packet) {
                    Some(obligation) => {
                        assert_eq!(obligation.packet(), PACKET, "received wrong packet");
                    }
                    None => panic!("receiving router did not attempt to receive a packet"),
                }
            }),
        },
    ]);
}

/// The context in which a peer test program runs.
struct PeerCtx<'r> {
    init_config: config::Router,
    configurator: ConfiguratorHandle<'r>,
    worker: WorkerHandle<'r>,

    sockets: Vec<UdpSocket>,
    peers: HashMap<PeerId, Vec<SocketAddr>>,
}

struct PeerSpec {
    id: PeerId,
    addr_count: usize,
    entrypoint: Box<dyn FnOnce(PeerCtx) + Send>,
}

impl<'r> PeerCtx<'r> {
    fn run(peers: Vec<PeerSpec>) {
        let mut sockets: HashMap<PeerId, Vec<UdpSocket>> = peers
            .iter()
            .map(|spec| {
                (
                    spec.id,
                    (0..spec.addr_count)
                        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
                        .inspect(|s| s.set_nonblocking(true).unwrap())
                        .collect(),
                )
            })
            .collect();

        let peer_addrs: HashMap<PeerId, Vec<SocketAddr>> = peers
            .iter()
            .map(|spec| {
                (
                    spec.id,
                    sockets[&spec.id]
                        .iter()
                        .map(|s| s.local_addr().unwrap())
                        .collect(),
                )
            })
            .collect();

        thread::scope(move |s| {
            for spec in peers {
                let peer_addrs = peer_addrs.clone();
                let sockets = sockets.remove(&spec.id).unwrap();

                s.spawn(move || {
                    let init_config = config::Router {
                        local_id: spec.id,
                        recv_addrs: peer_addrs.get(&spec.id).unwrap().iter().copied().collect(),
                        recv_tunnels: HashMap::new(),
                        send_tunnels: HashMap::new(),
                    };

                    let router = Router::new(&init_config);
                    (spec.entrypoint)(PeerCtx {
                        init_config,
                        configurator: router.configurator(),
                        worker: router.worker(),
                        sockets,
                        peers: peer_addrs,
                    });
                });
            }
        });
    }

    fn possible_links_to(&self, peer_id: PeerId) -> HashSet<Link> {
        self.sockets
            .iter()
            .map(|s| s.local_addr().unwrap())
            .flat_map(|local| {
                self.peers[&peer_id]
                    .iter()
                    .map(move |&remote| Link { local, remote })
            })
            .collect()
    }

    fn receive(&self) -> Vec<PacketMessage<Vec<u8>, auth::Unknown, text::Ciphertext>> {
        self.sockets
            .iter()
            .filter_map(|s| {
                let mut buf = vec![0; 1024];

                match s.recv(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        Some(PacketMessage::from_buffer(buf).expect("received invalid packet"))
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
                    Err(err) => panic!("error receiving: {}", err),
                }
            })
            .collect()
    }

    fn receive_block(&self) -> Vec<PacketMessage<Vec<u8>, auth::Unknown, text::Ciphertext>> {
        loop {
            let packets = self.receive();

            if !packets.is_empty() {
                return packets;
            }

            thread::sleep(Duration::from_millis(1));
        }
    }

    fn fulfill_send(&self, obligation: SendPacket) -> Vec<u8> {
        let socket = self
            .sockets
            .iter()
            .find(|s| s.local_addr().unwrap() == obligation.link().local)
            .expect("no socket for link specified by router");

        socket
            .send_to(obligation.message().as_buffer(), obligation.link().remote)
            .unwrap();

        obligation.fulfill()
    }
}
