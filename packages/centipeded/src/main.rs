use std::{
    env,
    error::Error,
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
use miette::{Context, Diagnostic, IntoDiagnostic, Report, Result};
use rand::thread_rng;
use thiserror::Error;

#[derive(Debug, clap::Parser)]
struct Opt {
    /// Path to config file.
    config: PathBuf,

    /// Number of workers to spawn.
    /// Defaults to the number of CPUs.
    #[clap(long, short, default_value_t = num_cpus::get())]
    workers: usize,
}

fn main() -> Result<()> {
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init_timed();

    let opt = <Opt as clap::Parser>::parse();
    log::debug!("opt: {:#?}", opt);

    let config: config::Centipede = toml::from_str(
        std::fs::read_to_string(&opt.config)
            .expect("failed to open config file")
            .as_str(),
    )
    .into_diagnostic()
    .wrap_err("failed to parse config")?;
    log::debug!("config: {:#?}", config);

    let now = SystemTime::now();
    let (mut controller, init_router_config) = Controller::new(
        now,
        ed25519_dalek::SigningKey::from_bytes(&config.private_key),
        thread_rng(),
    );
    for peer in config.peers {
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&peer.public_key)
            .into_diagnostic()
            .wrap_err("peer configuration had invalid public key")?;

        controller.listen(
            now,
            public_key,
            peer.local_addrs.into_iter().collect(),
            peer.max_heartbeat_interval,
        );

        if !peer.remote_addrs.is_empty() {
            controller.initiate(now, public_key, peer.remote_addrs);
        }
    }

    let router = Router::new(&init_router_config);

    let tun_dev = hypertube::builder()
        .with_name(config.interface_name)
        .with_address(config.address.address())
        .with_netmask(config.address.network())
        .with_pi(false)
        .with_num_queues(opt.workers)
        .with_up(true)
        .build()
        .into_diagnostic()
        .wrap_err("failed to create tun device")?;

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

    tokio::runtime::Builder::new_current_thread()
        .build()
        .into_diagnostic()?;

    thread::scope(|s| {
        {
            let shutdown = shutdown.clone();
            let worker = Worker::new(
                router.worker(),
                control_message_sink.clone(),
                tun_dev
                    .queue_nonblocking(0)
                    .into_diagnostic()
                    .wrap_err("failed to get TUN queue 0 (for the special first worker)")?,
            )
            .wrap_err("failed to create worker 0")?;

            s.spawn(move || worker_loop(worker, 0, shutdown, Some(rx_outgoing_control)));
        }

        for i in 1..opt.workers {
            let shutdown = shutdown.clone();
            let worker = Worker::new(
                router.worker(),
                control_message_sink.clone(),
                tun_dev
                    .queue_nonblocking(i)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("failed to get TUN queue {}", i))?,
            )
            .wrap_err_with(|| format!("failed to create worker {}", i))?;

            s.spawn(move || worker_loop(worker, i, shutdown, None));
        }

        log::info!("spawned {} worker threads", opt.workers);

        let router_configurator = router.configurator();
        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("received shutdown signal, waiting for workers to finish...");
                break;
            }

            let incoming = match rx_incoming_control.recv_timeout(Duration::from_millis(10)) {
                Ok(incoming) => Some(incoming),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                res => {
                    return res
                        .map(|_| ())
                        .into_diagnostic()
                        .wrap_err("failed to receive from incoming control message channel")
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
                tx_outgoing_control
                    .send(outgoing)
                    .into_diagnostic()
                    .wrap_err("failed to send outgoing message using control message channel")?;
            }
        }

        Ok(())
    })
}

fn worker_loop(
    mut worker: Worker,
    thread_number: usize,
    shutdown: Arc<AtomicBool>,
    rx_outgoing_control: Option<mpsc::Receiver<centipede_control::OutgoingMessage>>,
) {
    let mut events = mio::Events::with_capacity(1024);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        if let Some(Ok(outgoing)) = rx_outgoing_control.as_ref().map(mpsc::Receiver::try_recv) {
            let res = worker.send_control_message::<Vec<u8>>(
                outgoing.from,
                outgoing.to,
                outgoing.message,
            );

            if let Err(e) = res {
                println!(
                    "{:?}",
                    Report::new(InWorkerThread {
                        inner: e,
                        thread_number
                    })
                );

                log::info!("shutting down due to error");
                shutdown.store(true, Ordering::Relaxed);
            }
        }

        if let Err(e) = worker.wait_and_handle(&mut events) {
            println!(
                "{:?}",
                Report::new(InWorkerThread {
                    inner: e,
                    thread_number
                })
            );

            log::info!("shutting down due to error");
            shutdown.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Error, Diagnostic)]
#[error("worker thread {thread_number} failed")]
struct InWorkerThread<E: Error + 'static> {
    /// The error that occurred in the worker thread.
    #[source]
    inner: E,

    /// The worker thread number.
    thread_number: usize,
}
