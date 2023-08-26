use std::{
    iter,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use super::*;

/// A [`Dispatcher`] that sends packets to all available links,
/// and deduplicates them on the other end.
pub struct RaceAllDispatcher {
    /// The configuration of this dispatcher.
    config: Config,

    /// The set of available links.
    links: Vec<LinkId>,

    /// The sequence numbers of incoming packets that have been seen.
    seen_seq: CircularConcurrentBitset,

    /// The "center" of the seen sequence set; i.e. the boundary between the backward and forward windows.
    /// This is the highest seen sequence number.
    seen_center: AtomicU64,

    /// The next sequence number to use for outgoing packets.
    next_seq: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Config {
    /// Number of packets to remember in the seen sequence set.
    pub backward_window: usize,
    /// Maximum size of sequence "jump" to maintain space for in the seen sequence set.
    pub forward_window: usize,
}

impl Dispatcher for RaceAllDispatcher {
    type Config = Config;

    fn new(config: Self::Config, links: Vec<LinkId>) -> Self {
        Self {
            config,

            links,

            next_seq: AtomicU64::new(0),

            seen_seq: CircularConcurrentBitset::new(config.backward_window + config.forward_window),
            seen_center: AtomicU64::new(0),
        }
    }

    fn dispatch_incoming(&self, nonce: [u8; 12]) -> IncomingAction {
        let seq = u64::from_be_bytes(nonce[4..].try_into().unwrap());
        let old_center = self.seen_center.fetch_max(seq, Ordering::SeqCst);

        // The packet is in or ahead of the forward window.
        if seq > old_center {
            // The former forward window is already zeroed,
            // so we zero from the end of the old forward window to the end of the new one.
            self.seen_seq.zero_range(
                (old_center as usize + self.config.forward_window)
                    ..(seq as usize + self.config.forward_window),
            );

            IncomingAction::WriteToTun
        }
        // The packet is in the backward window.
        else if seq >= old_center - self.config.backward_window as u64 {
            let already_seen = self.seen_seq.set(seq as usize, true);

            if already_seen {
                IncomingAction::Drop
            } else {
                IncomingAction::WriteToTun
            }
        }
        // The packet is before the backward window.
        else {
            IncomingAction::Drop
        }
    }

    fn dispatch_outgoing(&self, _packet: &[u8]) -> Self::OutgoingActionIter<'_> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);

        OutgoingActionIter {
            seq,
            links: &self.links,
        }
    }

    type OutgoingActionIter<'d> = OutgoingActionIter<'d>;
}

pub struct OutgoingActionIter<'d> {
    seq: u64,
    links: &'d [LinkId],
}

impl<'d> Iterator for OutgoingActionIter<'d> {
    type Item = OutgoingAction;

    fn next(&mut self) -> Option<Self::Item> {
        match *self.links {
            [] => None,
            [link, ..] => {
                // Remove the link from the list for the next iteration.
                self.links = &self.links[1..];

                let mut nonce = [0u8; 12];
                nonce[4..].copy_from_slice(&self.seq.to_be_bytes());

                Some(OutgoingAction { link, nonce })
            }
        }
    }
}

struct CircularConcurrentBitset {
    bits: Vec<AtomicBool>,
}

impl CircularConcurrentBitset {
    /// Creates a new bitset with the given size consisting of all zeroes.
    pub fn new(size: usize) -> Self {
        Self {
            bits: iter::repeat(false)
                .map(AtomicBool::new)
                .take(size)
                .collect(),
        }
    }

    /// Atomically gets the bit at the given index.
    pub fn get(&self, index: usize) -> bool {
        self.bits[index % self.size()].load(Ordering::SeqCst)
    }

    /// Atomically sets the bit at the given index to the given value.
    pub fn set(&self, index: usize, value: bool) -> bool {
        self.bits[index % self.size()].swap(value, Ordering::SeqCst)
    }

    /// Zeroes the range.
    /// Wraps around if necessary, but not more than once.
    /// Note that this is not atomic.
    pub fn zero_range(&self, mut range: Range<usize>) {
        if range.len() >= self.size() {
            range.end = range.start + self.size() - 1;
        }

        for i in range {
            self.set(i, false);
        }
    }

    /// The number of bits in this set.
    pub fn size(&self) -> usize {
        self.bits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circular_concurrent_bitset() {
        // Create a bitset with modulus 10.
        let bitset = CircularConcurrentBitset::new(10);

        // Basic get and set.
        assert_eq!(bitset.get(0), false);
        assert_eq!(bitset.set(0, true), false);
        assert_eq!(bitset.get(0), true);

        // Wrap around get and set.
        assert_eq!(bitset.get(13), false);
        assert_eq!(bitset.set(13, true), false);
        assert_eq!(bitset.get(13), true);

        // Range zeroing.
        bitset.set(1, true);
        bitset.set(2, true);
        bitset.set(4, true);
        bitset.set(9, true);

        bitset.zero_range(1..4); // Zero range [1, 2, 3]
        assert_eq!(bitset.get(0), true); // Bit 0 was not changed
        assert_eq!(bitset.get(1), false);
        assert_eq!(bitset.get(2), false);
        assert_eq!(bitset.get(3), false);
        assert_eq!(bitset.get(4), true); // Bit 4 was not changed
        assert_eq!(bitset.get(9), true); // Bit 9 was not changed

        bitset.zero_range(8..12); // Zero range [8, 9, 0, 1]
        for i in 0..10 {
            assert_eq!(bitset.get(i), i == 4);
        }
    }
}
