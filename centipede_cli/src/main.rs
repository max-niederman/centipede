#![feature(split_array)]

use std::{collections::HashSet, path::Path, thread};

use base64::prelude::*;

use config::Config;

mod config;

fn main() {
    pretty_env_logger::init();

    let args = std::env::args().collect::<Vec<_>>();
    let args: Vec<_> = args.iter().collect();

    if args.len() != 2 {
        eprintln!("Usage: centipede <config>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "--help" => {
            eprintln!("Usage: centipede <config>");
            std::process::exit(0);
        }
        "--version" => {
            eprintln!("centipede {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        "genkey" => {
            let key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            println!(
                "public key: {}",
                BASE64_STANDARD.encode(key.verifying_key().to_bytes())
            );
            println!("private key: {}", BASE64_STANDARD.encode(key.to_bytes()));

            std::process::exit(0);
        }
        config_path => daemon(config_path.as_ref()),
    }
}

fn daemon(config_path: &Path) {
    let config_raw = std::fs::read_to_string(config_path).expect("Failed to open config file.");
    let config: Config = toml::from_str(&config_raw).expect("Failed to parse config file.");
    log::info!("loaded config from {config_path:?}");

    let tun = hypertube::builder()
        .with_name(config.if_name.clone())
        .with_address(config.address.address())
        .with_netmask(config.address.network())
        .with_pi(false)
        .with_num_queues(config.workers)
        .with_up(true)
        .build()
        .unwrap();

    let spec = config.as_spec();

    let (tunnel_state, tunnel_trans) = centipede_tunnel::SharedState::new(
        *config
            .private_key()
            .verifying_key()
            .to_bytes()
            .split_array_ref::<8>()
            .0,
        config
            .peers
            .iter()
            .flat_map(|peer| peer.local_tunnel_addresses.iter())
            .fold(HashSet::new(), |mut acc, &addr| {
                acc.insert(addr);
                acc
            })
            .into_iter()
            .collect(),
    );

    thread::scope(|s| {
        let tunnel_state = &tunnel_state;
        let tun = &tun;

        for i in 0..config.workers {
            s.spawn(move || {
                centipede_tunnel::worker::entrypoint(
                    tunnel_state,
                    &tun.queue_nonblocking(i).unwrap(),
                )
                .unwrap();
            });
        }

        s.spawn(move || {
            centipede_control::daemon::entrypoint(tunnel_trans, spec, |_| {})
                .expect("control daemon failed")
        })
        .join()
        .unwrap()
    });
}
