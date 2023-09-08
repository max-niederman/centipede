use std::{num::NonZeroU32, thread};

use centipede::{config::Config, tun, tunnel, TunnelId};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

fn main() {
    let config_path = std::env::args().nth(1).expect("Usage: centipede <config>");
    let config_raw = std::fs::read_to_string(&config_path).expect("Failed to open config file.");
    let config: Config = toml::from_str(&config_raw).expect("Failed to parse config file.");
    dbg!(&config);

    let tun = tun::Device::new(Some(config.if_name.clone())).unwrap();
    tun.set_address(config.address.address()).unwrap();
    tun.set_network(config.address.network()).unwrap();
    tun.bring_up().unwrap();

    let tunnel_state = tunnel::State::new(config.recv_addresses.clone());

    {
        let mut trans = tunnel_state.transitioner();

        let mut next_tunnel_id = NonZeroU32::MIN;

        for tunnel in config.recv_tunnels {
            trans.create_receive_tunnel(
                TunnelId(next_tunnel_id),
                tunnel
                    .endpoints
                    .into_iter()
                    .map(|e| (e.id, ChaCha20Poly1305::new_from_slice(&e.key).unwrap()))
                    .collect(),
            );
            next_tunnel_id = next_tunnel_id.checked_add(1).unwrap();
        }

        for tunnel in config.send_tunnels {
            trans.create_send_tunnel(
                TunnelId(next_tunnel_id),
                tunnel.local_addresses,
                tunnel
                    .endpoints
                    .into_iter()
                    .map(|e| {
                        (
                            e.id,
                            e.address,
                            ChaCha20Poly1305::new_from_slice(&e.key).unwrap(),
                        )
                    })
                    .collect(),
            );
            next_tunnel_id = next_tunnel_id.checked_add(1).unwrap();
        }
    }

    thread::scope(|s| {
        for _ in 0..config.workers {
            s.spawn(|| {
                tunnel::worker::entrypoint(&tunnel_state, &tun).unwrap();
            });
        }
    });
}
