pub mod fanout;

use std::net::{SocketAddr, UdpSocket};

pub trait Dispatcher: Sync {
    /// Create a new dispatcher over a set of links.
    fn new(links: Vec<LinkSpec>) -> Self;

    /// Dispatch an incoming packet.
    fn dispatch_incoming(&self, link: LinkSpec, associated_data: [u8; 2]) -> IncomingAction;

    /// Dispatch an outgoing packet.
    fn dispatch_outgoing(&self, packet: &[u8]) -> OutgoingAction<Self::OutgoingLinksIter<'_>>;

    /// The type of the link iterator returned by [`Dispatcher::dispatch_outgoing`].
    type OutgoingLinksIter<'a>: Iterator<Item = LinkSpec>
    where
        Self: 'a;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkSpec {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncomingAction {
    WriteToTun,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutgoingAction<L> {
    pub links: L,
    pub associated_data: [u8; 2],
}
