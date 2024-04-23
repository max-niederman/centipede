#![feature(test)]

extern crate test;
use std::{mem, net::UdpSocket, thread, time::SystemTime};

use centipede_proto::PacketMessage;
use centipede_router::{config, Link, Router};

mod common;
use common::*;

#[bench]
fn half_duplex_small_packets(b: &mut test::Bencher) {
    b.iter(|| half_duplex_iter(8, 1_000));
}

#[bench]
fn half_duplex_large_packets(b: &mut test::Bencher) {
    b.iter(|| half_duplex_iter(1024, 1_000));
}

#[bench]
fn control_spawn_two_threads(b: &mut test::Bencher) {
    b.iter(|| {
        thread::scope(|s| {
            s.spawn(|| {});
            s.spawn(|| {});
        });
    });
}

/// Perform one iteration of a half-duplex test, spawning a sender and receiver thread and sending `num_packets` packets of size `packet_size` over a single link.
///
/// Note: `packet_size` must be at least 8 bytes, as the first 8 bytes of each packet are used to store a packet number.
fn half_duplex_iter(packet_size: usize, num_packets: usize) {
    thread::scope(|s| {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_addr = recv_socket.local_addr().unwrap();

        // receiver
        s.spawn(move || {
            let router = Router::new(&config::Router {
                local_id: [1; 8],
                recv_addrs: [recv_addr].into(),
                recv_tunnels: [(
                    [0; 8],
                    config::RecvTunnel {
                        initialized_at: SystemTime::UNIX_EPOCH,
                        cipher: dummy_cipher(),
                    },
                )]
                .into_iter()
                .collect(),
                send_tunnels: [].into(),
            });
            let mut worker = router.worker();

            let mut read_buf = vec![0; PacketMessage::measure(packet_size)];

            for i in 0..num_packets {
                let (n, sender) = recv_socket.recv_from(&mut read_buf).unwrap();

                let message = PacketMessage::from_buffer(&mut read_buf[..n]).unwrap_or_else(|e| {
                    panic!("received invalid packet from {sender} on iteration {i}: {e}")
                });

                let _ = worker
                    .handle_incoming(message)
                    .expect("router didn't oblige us to receive a packet");
            }
        });

        // sender
        s.spawn(move || {
            let router = Router::new(&config::Router {
                local_id: [0; 8],
                recv_addrs: [].into(),
                recv_tunnels: [].into(),
                send_tunnels: [(
                    [1; 8],
                    config::SendTunnel {
                        initialized_at: SystemTime::UNIX_EPOCH,
                        links: [Link {
                            local: recv_addr,
                            remote: recv_addr,
                        }]
                        .into(),
                        cipher: dummy_cipher(),
                    },
                )]
                .into(),
            });
            let mut worker = router.worker();

            let send_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

            println!(
                "sending from {} to {recv_addr}",
                send_socket.local_addr().unwrap(),
            );

            let mut read_buf = vec![0; packet_size];
            let mut write_buf = Vec::new();

            for i in 0..num_packets {
                read_buf[0..8].copy_from_slice(&i.to_ne_bytes());

                let mut obligations = worker.handle_outgoing(&mut read_buf);

                let obligation = obligations
                    .resume(mem::take(&mut write_buf))
                    .expect("router has a link to send over, but didn't oblige us to send");

                assert_eq!(
                    obligation.link().remote,
                    recv_addr,
                    "router obliged us to send over a nonexistent link"
                );

                send_socket
                    .send_to(obligation.message().as_buffer(), obligation.link().remote)
                    .unwrap();

                assert!(
                    obligations.resume(Vec::new()).is_none(),
                    "router obliged us to send over a nonexistent link"
                );
            }
        });
    });
}
