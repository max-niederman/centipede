use std::{
    iter,
    net::SocketAddr,
    time::{Duration, SystemTime},
    vec,
};

use centipede_proto::control::{Content, Message};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use centipede_control::*;

/// Test that the state of a new controller is as expected.
#[test]
fn construction() {
    let rng = test_rng();

    for private_key in test_keys(rng.clone()) {
        for mut clock in test_clocks(rng.clone()) {
            println!(
                "testing controller construction with clock = {clock:?} and pk = {private_key:?}"
            );

            let (mut controller, router_config) =
                Controller::new(clock.now(), private_key.clone(), rng.clone());

            clock.increment(Duration::from_millis(1));

            assert_eq!(
                router_config.local_id,
                public_key_to_peer_id(&private_key.verifying_key()),
                "controller should start with a local ID from the top 8 bytes of the public key"
            );
            assert!(
                router_config.recv_addrs.is_empty(),
                "controller should start with no recv addrs"
            );
            assert!(
                router_config.recv_tunnels.is_empty(),
                "controller should start with no recv tunnels"
            );
            assert!(
                router_config.send_tunnels.is_empty(),
                "controller should start with no send tunnels"
            );

            let events = controller.poll(clock.now());

            assert!(
                events.router_config.is_none(),
                "there should be no router config updates for a new controller"
            );
            assert!(
                events.outgoing_messages.is_empty(),
                "there should be no outgoing messages for a new controller"
            );
        }
    }
}

/// Tests the results of calling `listen`.
#[test]
fn listen() {
    let mut rng = rand_chacha::ChaChaRng::from_seed([172; 32]);

    let mut peer_key = ed25519_dalek::SigningKey::generate(&mut rng);

    for private_key in test_keys(rng.clone()) {
        for mut clock in test_clocks(rng.clone()) {
            println!("testing listen with clock = {clock:?} and pk = {private_key:?}");

            let (mut controller, _) =
                Controller::new(clock.now(), private_key.clone(), rng.clone());

            clock.increment(Duration::from_millis(1));

            let local_addr = SocketAddr::new([127, 0, 0, 1].into(), 1234);
            let remote_addr = SocketAddr::new([127, 0, 0, 2].into(), 45678);
            controller.listen(
                clock.now(),
                peer_key.verifying_key(),
                [local_addr].into_iter().collect(),
                Duration::from_secs(60),
            );

            clock.increment(Duration::from_millis(1));

            let events = controller.poll(clock.now());

            let router_config = events
                .router_config
                .expect("controller should produce a router config after listen");
            assert!(
                router_config
                    .recv_addrs
                    .is_superset(&iter::once(local_addr).collect()),
                "controller should have the recv addrs after listen"
            );
            assert!(
                    router_config.recv_tunnels.is_empty(),
                    "there can't be any recv tunnels immediately after an initial listen, since we have not yet performed the handshake"
                );
            assert!(
                    router_config.send_tunnels.is_empty(),
                    "there can't be any send tunnels immediately after an initial listen, since we have not yet performed the handshake"
                );

            assert!(
                events.outgoing_messages.is_empty(),
                "there should be no outgoing messages immediately after listen"
            );

            clock.increment(Duration::from_secs(10));

            let peer_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let handshake_timestamp = clock.now();
            controller.handle_incoming(
                clock.now(),
                IncomingMessage {
                    from: remote_addr,
                    message: Message::new(
                        &peer_key,
                        private_key.verifying_key(),
                        Content::Initiate {
                            handshake_timestamp,
                            ecdh_public_key: (&peer_secret).into(),
                            max_heartbeat_interval: Duration::from_secs(60),
                        },
                    )
                    .forget_auth(),
                },
            );

            let events = controller.poll(clock.now());

            let router_config = events
                    .router_config
                    .expect("controller should produce a router config after listening for and receiving an incoming initiate");
            assert!(
                    router_config.recv_tunnels.get(&public_key_to_peer_id(&peer_key.verifying_key())).is_some(),
                    "controller should have a recv tunnel after listening for and receiving an incoming initiate"
                );
            assert!(
                router_config
                    .send_tunnels
                    .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                    .is_none(),
                "controller cannot know where to send packets until receiving heartbeats"
            );

            let mut outgoing_msgs = events.outgoing_messages.into_iter();

            let response = outgoing_msgs
                .next()
                .expect("a listening controller should respond to handshakes immediately");
            assert_eq!(
                response.from, local_addr,
                "response must be from the local address"
            );
            assert_eq!(
                response.to, remote_addr,
                "response must be to the remote address"
            );
            assert_eq!(
                response.message.sender(),
                &private_key.verifying_key(),
                "response should be from the local peer"
            );
            match response.message.content() {
                    Content::InitiateAcknowledge {
                        handshake_timestamp: timestamp,
                        ..
                    } => {
                        assert_eq!(
                            *timestamp, handshake_timestamp,
                            "initiate acknowledgement should echo the timestamp from the incoming initiate"
                        );
                    }
                    _ => panic!("controller should respond to an incoming initiate with an initiate acknowledgement"),
                }

            let heartbeat = outgoing_msgs.next().expect(
                "a listening controller should send heartbeats immediately after the handshake",
            );
            assert_eq!(
                heartbeat.message.sender(),
                &private_key.verifying_key(),
                "heartbeat should be from the local peer"
            );
            assert_eq!(
                heartbeat.message.content(),
                &Content::Heartbeat,
                "second message from a listening controller should be the first heartbeat"
            );

            assert!(
                outgoing_msgs.next().is_none(),
                "there should be no more outgoing messages after the first heartbeat"
            );
        }
        peer_key = private_key;
    }
}

#[test]
fn initiate() {
    let mut rng = rand_chacha::ChaChaRng::from_seed([172; 32]);

    let mut peer_key = ed25519_dalek::SigningKey::generate(&mut rng);

    for private_key in test_keys(rng.clone()) {
        for mut clock in test_clocks(rng.clone()) {
            for wait_to_initiate in [false, true] {
                println!("testing initiate with clock = {clock:?}, pk = {private_key:?}, and wait_to_initiate = {wait_to_initiate}");

                let (mut controller, _) = Controller::new(clock.now(), private_key.clone(), rng.clone());

                clock.increment(Duration::from_millis(1));

                let local_addr = SocketAddr::new([127, 0, 0, 1].into(), 1234);
                controller.listen(
                    clock.now(),
                    peer_key.verifying_key(),
                    [local_addr].into_iter().collect(),
                    Duration::from_secs(60),
                );

                // get the post-listen router config out of the way to test the effect of `initiate`
                let _ = controller.poll(clock.now());

                if wait_to_initiate {
                    clock.increment(Duration::from_secs(10));
                }

                let remote_addr = SocketAddr::new([127, 0, 0, 2].into(), 5678);
                controller.initiate(clock.now(), peer_key.verifying_key(), vec![remote_addr]);

                let mut events = controller.poll(clock.now());

                assert!(
                    events.router_config.is_none(),
                    "handshake initiation should not change the router config immediately"
                );

                let handshake_timestamp = clock.now();
                let initiate = events
                    .outgoing_messages
                    .pop()
                    .expect("initiating controller should send an initiate immediately");

                assert_eq!(
                    initiate.from, local_addr,
                    "initiate must be from the local address"
                );
                assert_eq!(
                    initiate.to, remote_addr,
                    "initiate must be to the remote address"
                );
                assert_eq!(
                    initiate.message.sender(),
                    &private_key.verifying_key(),
                    "initiate should be from the local peer"
                );
                match initiate.message.content() {
                    Content::Initiate {
                        handshake_timestamp: timestamp,
                        ..
                    } => {
                        assert!(
                            *timestamp == handshake_timestamp,
                            "initiate should have the current timestamp"
                        );
                    }
                    _ => panic!("initiating controller should send an initiate immediately"),
                }

                assert!(
                    events.outgoing_messages.is_empty(),
                    "there should be no more outgoing messages after the first initiate"
                );

                clock.increment(Duration::from_millis(500));

                controller.handle_incoming(
                    clock.now(),
                    IncomingMessage {
                        from: remote_addr,
                        message: Message::new(
                            &peer_key,
                            private_key.verifying_key(),
                            Content::InitiateAcknowledge {
                                handshake_timestamp,
                                ecdh_public_key: (&x25519_dalek::EphemeralSecret::random_from_rng(
                                    &mut rng,
                                ))
                                    .into(),
                                max_heartbeat_interval: Duration::from_secs(60),
                            },
                        )
                        .forget_auth(),
                    },
                );

                let mut events = controller.poll(clock.now());

                let router_config = events.router_config.expect(
                        "controller should produce a router config after initiating and receiving an incoming initiate acknowledgement",
                    );
                assert!(
                        router_config
                            .recv_tunnels
                            .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                            .is_some(),
                        "controller should have a recv tunnel after initiating and receiving an incoming initiate acknowledgement"
                    );
                assert!(
                        router_config
                            .send_tunnels
                            .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                            .is_some(),
                        "controller should have a recv tunnel after initiating and receiving an incoming initiate acknowledgement"
                    );
                assert!(
                    router_config
                        .send_tunnels
                        .get(&public_key_to_peer_id(&peer_key.verifying_key()))
                        .unwrap()
                        .links
                        .is_empty(),
                    "controller cannot know where to send packets until receiving heartbeats"
                );

                let heartbeat = events.outgoing_messages.pop().expect(
                        "an initiating controller should send heartbeats immediately after the handshake",
                    );
                assert_eq!(
                    heartbeat.message.sender(),
                    &private_key.verifying_key(),
                    "heartbeat should be from the local peer"
                );
                assert_eq!(
                        heartbeat.message.content(),
                        &Content::Heartbeat,
                        "second message from an initiating controller should be stamped with the current time"
                    );

                assert!(
                    events.outgoing_messages.is_empty(),
                    "there should be no more outgoing messages after the first heartbeat"
                );
            }
        }
        peer_key = private_key;
    }
}

// TODO: add tests for receiving heartbeats, disconnecting
// TODO: add test using two controllers to test that they can communicate

/// Convert a public key to a peer ID by taking its first 8 bytes.
fn public_key_to_peer_id(public_key: &ed25519_dalek::VerifyingKey) -> [u8; 8] {
    public_key.to_bytes()[..8].try_into().unwrap()
}

#[derive(Debug)]
struct TestClock {
    now: SystemTime,
}

impl TestClock {
    fn now(&self) -> SystemTime {
        self.now
    }

    fn increment(&mut self, duration: Duration) {
        self.now += duration;
    }
}

fn test_clocks(mut rng: ChaChaRng) -> impl Iterator<Item = TestClock> {
    iter::once(Duration::ZERO)
        .chain(
            iter::repeat_with(move || {
                Duration::from_secs(rng.gen_range(0..(100 * 365 * 24 * 60 * 60)))
            })
            .take(31),
        )
        .map(|dur| TestClock {
            now: SystemTime::UNIX_EPOCH + dur,
        })
}

fn test_keys(mut rng: ChaChaRng) -> impl Iterator<Item = ed25519_dalek::SigningKey> {
    iter::repeat_with(move || ed25519_dalek::SigningKey::generate(&mut rng)).take(32)
}

fn test_rng() -> rand_chacha::ChaChaRng {
    rand_chacha::ChaChaRng::from_seed([42; 32])
}
