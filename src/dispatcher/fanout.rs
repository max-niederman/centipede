use std::sync::atomic::{AtomicU16, Ordering};

use super::*;

pub struct FanoutDispatcher {
    links: Vec<LinkSpec>,

    next_seq: AtomicU16,
}

impl Dispatcher for FanoutDispatcher {
    fn new(links: Vec<LinkSpec>) -> Self {
        Self {
            links,
            next_seq: AtomicU16::new(0),
        }
    }

    fn dispatch_incoming(&self, _link: LinkSpec, associated_data: [u8; 2]) -> IncomingAction {
        todo!()
    }

    fn dispatch_outgoing(&self, _packet: &[u8]) -> OutgoingAction<Self::OutgoingLinksIter<'_>> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);

        OutgoingAction {
            links: self.links.iter().copied(),
            associated_data: seq.to_be_bytes(),
        }
    }

    type OutgoingLinksIter<'a> = std::iter::Copied<std::slice::Iter<'a, LinkSpec>>;
}
