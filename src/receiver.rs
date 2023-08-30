use std::{
    io::{self, Write},
    iter,
    mem::MaybeUninit,
    net::SocketAddr,
    ops::Range,
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use chacha20poly1305::ChaCha20Poly1305;
use mio::{unix::SourceFd, Poll};
use socket2::{Domain, Socket};

use crate::{
    message::{self, Message},
    EndpointId,
};

pub struct Receiver {
    /// Socket addresses on which to listen.
    listen_addrs: Vec<SocketAddr>,

    /// Ciphers for each endpoint.
    ciphers: flurry::HashMap<EndpointId, ChaCha20Poly1305>,

    /// The deduplicator.
    deduplicator: Deduplicator,
}

impl Receiver {
    pub fn new(listen_addrs: Vec<SocketAddr>) -> Self {
        Self {
            listen_addrs,
            ciphers: flurry::HashMap::new(),
            deduplicator: Deduplicator::new(16 * 1024, 32 * 1024), // TODO: i completely made these up, they should be tested
        }
    }

    /// Worker loop for receiving packets.
    pub fn worker(&self, mut tun_queue: tun::platform::Queue) -> io::Result<!> {
        // Create a mio poller.
        let mut poll = Poll::new()?;
        let mut events = mio::Events::with_capacity(1024);

        // Bind to each listen address.
        let sockets: Vec<_> = self.listen_addrs.iter().map(bind_socket).try_collect()?;

        // Register all sockets with the poller.
        for (i, socket) in sockets.iter().enumerate() {
            poll.registry().register(
                &mut SourceFd(&socket.as_raw_fd()),
                mio::Token(i),
                mio::Interest::READABLE,
            )?;
        }

        loop {
            poll.poll(&mut events, None)?;

            for event in events.iter() {
                let socket = &sockets[event.token().0];

                let mut buf = MaybeUninit::uninit_array::<{ message::MTU }>();
                let (len, addr) = socket.recv_from(&mut buf)?; // TODO: does this need to be non-blocking?
                let datagram = unsafe { MaybeUninit::slice_assume_init_mut(&mut buf[..len]) };

                let message = match Message::parse(datagram) {
                    Ok(message) => message,
                    Err(e) => {
                        log::warn!("failed to parse message: {}", e);
                        continue;
                    }
                };

                let cipher_guard = self.ciphers.guard();

                let cipher = match self.ciphers.get(&message.link, &cipher_guard) {
                    Some(cipher) => cipher,
                    None => {
                        log::warn!("received message for unknown endpoint");
                        continue;
                    }
                };

                let message = match Message::decode(cipher, datagram) {
                    Ok(message) => message,
                    Err(e) => {
                        log::warn!("failed to decode message: {}", e);
                        continue;
                    }
                };

                drop(cipher_guard);

                match self.deduplicator.observe(message.seq) {
                    Some(PacketRecollection::Seen) | None => {}
                    Some(PacketRecollection::New) => {
                        tun_queue.write(&message.packet)?;
                    }
                }
            }
        }
    }
}

fn bind_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, socket2::Type::DGRAM, None)?;

    // Each worker will bind to the same addresses.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;

    socket.bind(&(*addr).into())?;

    Ok(socket)
}

struct Deduplicator {
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

impl Deduplicator {
    /// Creates a new deduplicator with the given window sizes.
    fn new(forward_window: usize, backward_window: usize) -> Self {
        Self {
            forward_window,
            backward_window,
            seen_packets: CircularConcurrentBitset::new(forward_window + backward_window),
            seen_last: AtomicU64::new(0),
        }
    }

    /// Observes a packet with the given sequence number,
    /// returning whether it's been seen before, if possible.
    fn observe(&self, seq: u64) -> Option<PacketRecollection> {
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
        else if seq >= old_last - self.backward_window as u64 {
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

enum PacketRecollection {
    New,
    Seen,
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
