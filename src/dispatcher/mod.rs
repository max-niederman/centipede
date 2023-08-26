pub mod race_all;

use std::net::{SocketAddr, UdpSocket};

pub type Nonce = [u8; 12];

pub trait Dispatcher: Sync {
    type Config;

    /// Create a new dispatcher over a set of links.
    fn new(config: Self::Config, links: Vec<LinkId>) -> Self;

    /// Dispatch an incoming packet.
    fn dispatch_incoming(&self, nonce: [u8; 12]) -> IncomingAction;

    /// Dispatch an outgoing packet.
    fn dispatch_outgoing(&self, packet: &[u8]) -> Self::OutgoingActionIter<'_>;

    /// The type of the action iterator returned by [`Dispatcher::dispatch_outgoing`].
    type OutgoingActionIter<'d>: Iterator<Item = OutgoingAction>
    where
        Self: 'd;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkId(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncomingAction {
    WriteToTun,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutgoingAction {
    pub link: LinkId,
    pub nonce: [u8; 12],
}
