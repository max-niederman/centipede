pub mod race_all;

use crate::LinkId;

pub type Nonce = [u8; 8];

pub trait Dispatcher: Sync {
    /// Dispatch an incoming packet.
    fn dispatch_incoming(&self, nonce: Nonce) -> IncomingAction;

    /// Dispatch an outgoing packet.
    fn dispatch_outgoing(&self, packet: &[u8]) -> Self::OutgoingActionIter<'_>;

    /// The type of the action iterator returned by [`Dispatcher::dispatch_outgoing`].
    type OutgoingActionIter<'d>: Iterator<Item = OutgoingAction>
    where
        Self: 'd;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncomingAction {
    WriteToTun,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutgoingAction {
    pub link: LinkId,
    pub nonce: Nonce,
}

impl<'a, D> Dispatcher for &'a D
where
    D: Dispatcher,
{
    fn dispatch_incoming(&self, nonce: Nonce) -> IncomingAction {
        (**self).dispatch_incoming(nonce)
    }

    fn dispatch_outgoing(&self, packet: &[u8]) -> Self::OutgoingActionIter<'_> {
        (**self).dispatch_outgoing(packet)
    }

    type OutgoingActionIter<'d> = <D as Dispatcher>::OutgoingActionIter<'d>
    where
        Self: 'd;
}
