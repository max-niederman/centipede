use std::{
    iter,
    ops::Range,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

#[derive(Debug)]
pub struct PacketMemory {
    /// Number of previously seen packets to remember.
    forward_window: usize,
    /// Maximum size of jump in sequence numbers for which to maintain space.
    backward_window: usize,

    /// Bitset remembering which packets have been seen.
    seen_packets: CircularConcurrentBitset,

    /// The greatest sequence number that's been seen.
    /// This is also the boundary between the forward and backward windows.
    seen_max: AtomicU64,
}

impl PacketMemory {
    /// Creates a new [`PacketMemory`] with the given window sizes.
    pub fn new(forward_window: usize, backward_window: usize) -> Self {
        Self {
            forward_window,
            backward_window,
            seen_packets: CircularConcurrentBitset::new(forward_window + backward_window + 1),
            seen_max: AtomicU64::new(0),
        }
    }

    /// Observes a packet with the given sequence number,
    /// returning whether it's been seen before, if possible.
    pub fn observe(&self, seq: u64) -> PacketRecollection {
        let old_max = self.seen_max.load(Ordering::SeqCst);

        // The packet is ahead of the forward window.
        if seq > (old_max + self.forward_window as u64) {
            PacketRecollection::Confusing
        }
        // The packet is in the forward window.
        else if seq > old_max {
            // Update the maximum seen sequence number.
            self.seen_max.fetch_max(seq, Ordering::SeqCst);

            // Set the packet as seen.
            self.seen_packets.set(seq as usize, true);

            // The former forward window is already zeroed,
            // so we zero from the end of the old forward window to the end of the new one.
            self.seen_packets.zero_range(
                (old_max as usize + self.forward_window + 1)
                    ..(seq as usize + self.forward_window + 1),
            );

            PacketRecollection::New
        }
        // The packet is in the backward window.
        else if (self.backward_window as u64 > old_max)
            || seq >= (old_max - self.backward_window as u64)
        {
            let already_seen = self.seen_packets.set(seq as usize, true);

            if already_seen {
                PacketRecollection::Seen
            } else {
                PacketRecollection::New
            }
        }
        // The packet is before the backward window.
        else {
            PacketRecollection::Confusing
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketRecollection {
    /// The packet is new and not confusing.
    /// This can be the case if the packet is in backward window,
    /// and is always the case if the packet is in the forward window.
    New,
    /// The packet has been seen before.
    /// This can be the case if the packet is in the backward window,
    /// and is never the case if the packet is in the forward window or elsewhere.
    Seen,
    /// The packet is confusing, and ignored by the memory.
    /// This happens iff the packet is before the backward window or ahead of the forward window.
    Confusing,
}

impl Default for PacketMemory {
    fn default() -> Self {
        Self::new(16 * 1024, 32 * 1024)
    }
}

#[derive(Debug)]
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
    #[cfg(test)]
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

    macro_rules! assert_recollection {
        ($memory:expr, $id:expr, $seq:literal : new) => {{
            let recollection = $memory.observe($seq);
            assert!(
                recollection == PacketRecollection::New,
                r#"
recollection test {id} failed:
    expected sequence number {seq} to have recollection New,
    but it had recollection {recollection:?} instead
                "#,
                id = $id,
                seq = $seq,
            );
        }};
        ($memory:expr, $id:expr, $seq:literal : seen) => {{
            let recollection = $memory.observe($seq);
            assert!(
                recollection == PacketRecollection::Seen,
                r#"
recollection test {id} failed:
    expected sequence number {seq} to have recollection Seen,
    but it had recollection {recollection:?} instead
                "#,
                id = $id,
                seq = $seq,
            );
        }};
        ($memory:expr, $id:expr, $seq:literal : confusing) => {{
            let recollection = $memory.observe($seq);
            assert!(
                recollection == PacketRecollection::Confusing,
                r#"
recollection test {id} failed:
    expected sequence number {seq} to be confusing,
    but it had recollection {recollection:?}
                "#,
                id = $id,
                seq = $seq,
            );
        }};
    }

    macro_rules! recollection_test {
        ($name:ident, $memory:expr, { $( $seq:literal : $rec:ident ; )* }) => {
            #[test]
            #[allow(unused_assignments)]
            fn $name() {
                let memory = $memory;
                let mut i: usize = 0;
                $(
                    println!("memory = {:#?}", memory);
                    println!("recollection test {i}: seq = {seq}, rec = {exp}", i = i, seq = $seq, exp = stringify!($rec));

                    assert_recollection!(memory, i, $seq : $rec);

                    i += 1;
                )*
            }
        };
    }

    recollection_test!(
        monotonically_increasing_always_new,
        PacketMemory::new(2, 2),
        {
            0: new;
            1: new;
            2: new;
            3: new;
            4: new;
        }
    );

    recollection_test!(
        duplicate_within_backward_window,
        PacketMemory::new(2, 2),
        {
            0: new;
            1: new;
            2: new;
            2: seen;

            3: new;
            4: new;
            5: new;
            6: new;
            5: seen;
        }
    );

    recollection_test!(
        duplicate_before_backward_window,
        PacketMemory::new(2, 2),
        {
            0: new;
            1: new;
            2: new;
            3: new;
            0: confusing;
            1: seen;
        }
    );

    recollection_test!(
        ahead_of_forward_window,
        PacketMemory::new(2, 2),
        {
            0: new;
            1: new;
            2: new;
            10: confusing;
            1: seen;
            2: seen;
        }
    );
}
