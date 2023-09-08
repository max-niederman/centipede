use std::{
    iter,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

pub struct PacketMemory {
    /// Number of previously seen packets to remember.
    forward_window: usize,
    /// Maximum size of jump in sequence numbers for which to maintain space.
    backward_window: usize,

    /// Bitset remembering which packets have been seen.
    seen_packets: CircularConcurrentBitset,

    /// The sequence number of the last packet seen.
    /// This is also the boundary between the forward and backward windows.
    seen_last: AtomicU64,
}

impl PacketMemory {
    /// Creates a new [`PacketMemory`] with the given window sizes.
    pub fn new(forward_window: usize, backward_window: usize) -> Self {
        Self {
            forward_window,
            backward_window,
            seen_packets: CircularConcurrentBitset::new(forward_window + backward_window),
            seen_last: AtomicU64::new(0),
        }
    }

    /// Observes a packet with the given sequence number,
    /// returning whether it's been seen before, if possible.
    pub fn observe(&self, seq: u64) -> Option<PacketRecollection> {
        let old_last = self.seen_last.fetch_max(seq, Ordering::SeqCst);

        // The packet is in or ahead of the forward window.
        if seq > old_last {
            // The former forward window is already zeroed,
            // so we zero from the end of the old forward window to the end of the new one.
            self.seen_packets.zero_range(
                (old_last as usize + self.forward_window)..(seq as usize + self.forward_window),
            );

            Some(PacketRecollection::New)
        }
        // The packet is in the backward window.
        else if (self.backward_window as u64 > old_last)
            || seq >= old_last - self.backward_window as u64
        {
            let already_seen = self.seen_packets.set(seq as usize, true);

            if already_seen {
                Some(PacketRecollection::Seen)
            } else {
                Some(PacketRecollection::New)
            }
        }
        // The packet is before the backward window.
        else {
            None
        }
    }
}

pub enum PacketRecollection {
    New,
    Seen,
}

impl Default for PacketMemory {
    fn default() -> Self {
        Self::new(16 * 1024, 32 * 1024)
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
