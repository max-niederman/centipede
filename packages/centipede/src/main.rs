use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, SystemTime},
};

use centipede_control::{Controller, IncomingMessage};
use centipede_router::Router;
use centipede_worker::Worker;
use rand::thread_rng;

mod config;

#[derive(Debug, clap::Parser)]
struct Opt {
    /// Path to config file.
    config: PathBuf,
}

fn main() {
    pretty_env_logger::init();

    let opt = <Opt as clap::Parser>::parse();
    log::debug!("opt: {:#?}", opt);

    let config: config::Centipede = toml::from_str(
        std::fs::read_to_string(&opt.config)
            .expect("failed to open config file")
            .as_str(),
    )
    .expect("failed to parse config");
    log::debug!("config: {:#?}", config);

    let (mut controller, init_router_config) = Controller::new(
        SystemTime::now(),
        ed25519_dalek::SigningKey::from_bytes(&config.private_key),
        thread_rng(),
    );

    let router = Router::new(&init_router_config);
    let router_configurator = router.configurator();

    let tun_dev = hypertube::builder()
        .with_name(config.interface_name)
        .with_address(config.address.address())
        .with_netmask(config.address.network())
        .with_num_queues(config.workers)
        .build()
        .expect("failed to create tun device");

    let (tx_incoming_control, rx_incoming_control) =
        mpsc::channel::<centipede_control::IncomingMessage<Vec<u8>>>();
    let (tx_outgoing_control, rx_outgoing_control) =
        mpsc::channel::<centipede_control::OutgoingMessage>();
    let control_message_sink = Box::new(|from, message| {
        tx_incoming_control
            .send(IncomingMessage { from, message })
            .unwrap();
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    log::debug!("starting shutdown signal handler");
    ctrlc::set_handler({
        let shutdown = shutdown.clone();
        move || {
            shutdown.store(true, Ordering::SeqCst);
        }
    })
    .expect("failed to set shutdown signal handler");

    thread::scope(|s| {
        {
            let shutdown = shutdown.clone();
            let mut worker = Worker::new(
                router.worker(),
                control_message_sink.clone(),
                tun_dev
                    .queue_nonblocking(0)
                    .expect("failed getting first tun queue"),
            );

            s.spawn(move || {
                let mut events = mio::Events::with_capacity(1024);
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    if let Ok(outgoing) = rx_outgoing_control.try_recv() {
                        worker
                            .send_control_message::<Vec<u8>>(
                                outgoing.from,
                                outgoing.to,
                                outgoing.message,
                            )
                            .expect("failed sending control message");
                    }

                    worker.wait_and_handle(&mut events).unwrap();
                }
            });
        }

        for i in 1..config.workers {
            let shutdown = shutdown.clone();
            let mut worker = Worker::new(
                router.worker(),
                control_message_sink.clone(),
                tun_dev
                    .queue_nonblocking(i)
                    .expect("failed getting additional tun queue"),
            );
            s.spawn(move || {
                let mut events = mio::Events::with_capacity(1024);
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    worker.wait_and_handle(&mut events).unwrap();
                }
            });
        }

        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("Received shutdown signal, waiting for workers to finish...");
                break;
            }

            let incoming = match rx_incoming_control.recv_timeout(Duration::from_millis(10)) {
                Ok(incoming) => Some(incoming),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("incoming control message channel disconnected")
                }
            };

            let now = SystemTime::now();

            if let Some(incoming) = incoming {
                controller.handle_incoming(now, incoming);
            }

            let events = controller.poll(now);

            if let Some(new_router_config) = events.router_config {
                router_configurator.configure(&new_router_config);
            }

            for outgoing in events.outgoing_messages {
                tx_outgoing_control.send(outgoing).unwrap();
            }
        }
    });
}
