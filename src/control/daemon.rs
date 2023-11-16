use std::{
    error::Error,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use stakker::{
    actor, actor_new, call, fwd_to, ret_fail, ret_failthru, ret_nop, ret_shutdown,
    sync::{Channel, ChannelGuard},
    ActorOwn, Cx, Share, Stakker, StopCause,
};
use stakker_mio::MioPoll;

use crate::tunnel;

use super::{Controller, Spec};

/// A daemon command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    UpdateSpec(Spec),
    Stop,
}

/// The entrypoint of the control daemon.
pub fn entrypoint(
    tunnel_trans: tunnel::StateTransitioner,
    init_spec: Spec,
    commander: impl FnOnce(Channel<Command>),
) -> Result<(), Box<dyn Error>> {
    let mut stakker = Stakker::new(Instant::now());
    let mio_poll = MioPoll::new(
        &mut stakker,
        mio::Poll::new()?,
        mio::Events::with_capacity(1024),
        0,
    )?;

    let daemon = actor_new!(&mut stakker, Daemon, ret_nop!());

    let (cmd_channel, cmd_guard) = Channel::new(
        &mut stakker,
        fwd_to!([daemon], receive_command() as (Command)),
    );

    call!(
        [daemon],
        Daemon::new(Share::new(&*stakker, tunnel_trans), init_spec, cmd_guard)
    );

    commander(cmd_channel);

    let mut idle_pending = stakker.run(Instant::now(), false);
    while stakker.not_shutdown() {
        let max_dur = stakker.next_wait_max(Instant::now(), Duration::from_secs(10), idle_pending);
        let activity = mio_poll.poll(max_dur)?;
        idle_pending = stakker.run(Instant::now(), !activity);
    }

    match stakker.shutdown_reason() {
        Some(StopCause::Failed(e) | StopCause::Killed(e)) => Err(e),
        Some(StopCause::Stopped) => Ok(()),
        Some(StopCause::Dropped) => {
            unreachable!("stakked stopped unexpectedly")
        }
        Some(StopCause::Lost) => unreachable!("remote actors not used"),
        None => unreachable!("stakker shutdown without reason"),
    }
}

/// An actor redirecting configuration commands to the controller.
struct Daemon {
    /// The controller.
    controller: ActorOwn<Controller>,

    /// Guard keeping the command channel open.
    _cmd_guard: ChannelGuard,
}

impl Daemon {
    fn new(
        cx: &mut Cx<'_, Self>,
        tunnel_trans: Share<tunnel::StateTransitioner>,
        init_spec: Spec,
        cmd_guard: ChannelGuard,
    ) -> Option<Self> {
        let controller = actor!(
            cx,
            Controller::new(tunnel_trans, init_spec),
            ret_fail!(cx, "controller failed")
        );

        Some(Self {
            controller,
            _cmd_guard: cmd_guard,
        })
    }

    fn receive_command(&mut self, cx: &mut Cx<'_, Self>, cmd: Command) {
        match cmd {
            Command::UpdateSpec(spec) => {
                call!([self.controller], update_spec(spec))
            }
            Command::Stop => {
                // TODO: does this actually shut down the event loop?
                cx.stop();
            }
        }
    }
}
