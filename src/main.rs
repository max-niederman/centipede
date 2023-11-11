use std::{num::NonZeroU32, thread};

use centipede::{config::Config, tunnel};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

fn main() {
    pretty_env_logger::init();

    let config_path = std::env::args().nth(1).expect("Usage: centipede <config>");
    let config_raw = std::fs::read_to_string(&config_path).expect("Failed to open config file.");
    let config: Config = toml::from_str(&config_raw).expect("Failed to parse config file.");
    log::info!("loaded config from {config_path}");

    let tun = hypertube::builder()
        .with_name(config.if_name.clone())
        .with_address(config.address.address())
        .with_netmask(config.address.network())
        .with_pi(false)
        .with_num_queues(config.workers)
        .with_up(true)
        .build()
        .unwrap();

    let (tunnel_state, tunnel_trans) =
        tunnel::SharedState::new(todo!(), config.recv_addresses.clone());

    todo!("spawn control daemon");

    thread::scope(|s| {
        let tunnel_state = &tunnel_state;
        let tun = &tun;

        for i in 0..config.workers {
            s.spawn(move || {
                tunnel::worker::entrypoint(tunnel_state, &tun.queue_nonblocking(i).unwrap())
                    .unwrap();
            });
        }
    });
}
