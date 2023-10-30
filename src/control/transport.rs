use std::{
    io::{self, Read},
    mem::{self, MaybeUninit},
    net::SocketAddr,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mio::{net::TcpStream, Interest};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket};
use stakker::{actor, call, fail, fwd_to, ret_fail, stop, ActorOwn, Cx, Fwd};
use stakker_mio::{MioPoll, MioSource, Ready};

use super::message::Message;

/// An actor responsible for message transport with a peer.
pub struct PeerTransport {
    /// The stream of envelopes.
    stream: ActorOwn<Stream>,

    /// The public key of the peer.
    peer_key: VerifyingKey,

    /// The key of the local machine.
    local_key: SigningKey,

    /// A [`Fwd`] which receives inbound messages from the peer.
    receiver: Fwd<Message>,
}

impl PeerTransport {
    /// Create a new peer transport.
    pub fn new(
        cx: &mut Cx<'_, Self>,
        peer_key: VerifyingKey,
        local_key: SigningKey,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        receiver: Fwd<Message>,
    ) -> Option<Self> {
        let stream = connect(local_addr, remote_addr)
            .map(|tcp_stream| {
                actor!(
                    cx,
                    Stream::new(
                        tcp_stream,
                        fwd_to!([cx], handle_inbound_envelope() as (Envelope)),
                    ),
                    ret_fail!(cx, "failed to create stream")
                )
            })
            .ok()?;

        Some(Self {
            stream,
            local_key,
            peer_key,
            receiver,
        })
    }

    /// Send a message to the peer.
    pub fn send(&mut self, cx: &mut Cx<'_, Self>, message: &Message) {
        let envelope = match Envelope::serialize_and_sign(&message, &self.local_key) {
            Ok(envelope) => envelope,
            Err(err) => {
                fail!(cx, err);
                return;
            }
        };

        call!([self.stream], send(envelope));
    }

    /// Handle an inbound envelope.
    fn handle_inbound_envelope(&mut self, cx: &mut Cx<'_, Self>, envelope: Envelope) {
        match envelope.authenticate_and_deserialize() {
            Ok((public_key, message)) if public_key == self.peer_key => {
                self.receiver.fwd(message);
            }
            Ok((_, _)) => {
                fail!(cx, "received message from wrong peer");
            }
            Err(err) => {
                fail!(cx, err);
            }
        }
    }
}

fn connect(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(local_addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.bind(&local_addr.into())?;
    socket.connect(&remote_addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(TcpStream::from_std(socket.into()))
}

/// An actor responsible for sending and receiving message envelopes over a TCP stream.
struct Stream {
    /// The TCP stream.
    tcp_stream: MioSource<TcpStream>,

    /// A [`Fwd`] which receives messages from the stream.
    envelope_receiver: Fwd<Envelope>,

    /// The envelope-reading state of the stream.
    state: StreamState,
}

enum StreamState {
    ReadingLength,
    ReadingEnvelope {
        /// The buffer for the envelope.
        recv_buf: Vec<u8>,

        /// Number of bytes already read.
        bytes_read: usize,
    },
}

impl Default for StreamState {
    fn default() -> Self {
        Self::ReadingLength
    }
}

impl Stream {
    /// Create a new stream wrapping a TCP stream.  
    pub fn new(
        cx: &mut Cx<'_, Self>,
        tcp_stream: TcpStream,
        envelope_receiver: Fwd<Envelope>,
    ) -> Option<Self> {
        let mio_poll = cx.anymap_get::<MioPoll>();
        let tcp_stream = mio_poll
            .add(
                tcp_stream,
                Interest::READABLE,
                0,
                fwd_to!([cx], ready() as (Ready)),
            )
            .map_err(|err| cx.fail(err))
            .ok()?;

        Some(Self {
            tcp_stream,
            envelope_receiver,
            state: StreamState::ReadingLength,
        })
    }

    /// Handle a ready event on the TCP stream.
    fn ready(&mut self, cx: &mut Cx<'_, Self>, ready: Ready) {
        loop {
            self.state = match std::mem::take(&mut self.state) {
                StreamState::ReadingLength => {
                    // FIXME: we should probably handle the case where it starts blocking after reading just one byte
                    //        right now, it'll fuck everything up massively
                    let mut buf = [0; 2];
                    match self.tcp_stream.read_exact(&mut buf) {
                        Ok(()) => {
                            let len = u16::from_be_bytes(buf);
                            StreamState::ReadingEnvelope {
                                recv_buf: vec![0; len as usize],
                                bytes_read: 0,
                            }
                        }
                        Err(err) => match err.kind() {
                            io::ErrorKind::WouldBlock => break,
                            io::ErrorKind::UnexpectedEof => return stop!(cx),
                            _ => return fail!(cx, "failed to read envelope length: {}", err),
                        },
                    }
                }
                StreamState::ReadingEnvelope {
                    mut recv_buf,
                    bytes_read,
                } => match self.tcp_stream.read(&mut recv_buf[bytes_read..]) {
                    Ok(0) => return stop!(cx),
                    Ok(n) if bytes_read + n == recv_buf.len() => {
                        match bincode::deserialize(&recv_buf) {
                            Ok(envelope) => {
                                self.envelope_receiver.fwd(envelope);
                                StreamState::ReadingLength
                            }
                            Err(err) => {
                                return fail!(cx, "failed to deserialize envelope: {}", err)
                            }
                        }
                    }
                    Ok(n) => StreamState::ReadingEnvelope {
                        recv_buf,
                        bytes_read: bytes_read + n,
                    },
                    Err(err) => match err.kind() {
                        io::ErrorKind::WouldBlock => break,
                        io::ErrorKind::UnexpectedEof => return stop!(cx),
                        _ => return fail!(cx, "failed to read envelope: {}", err),
                    },
                },
            };
        }
    }

    /// Send an envelope over the TCP stream.
    pub fn send(&mut self, cx: &mut Cx<'_, Self>, envelope: Envelope) {
        match bincode::serialize_into(&mut *self.tcp_stream, &envelope) {
            Ok(()) => {}
            Err(box bincode::ErrorKind::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                // TODO: handle this properly
                fail!(cx, "sending envelope would block")
            }
            Err(err) => fail!(cx, "failed to serialize envelope: {}", err),
        }
    }
}

/// An envelope for a message.
///
/// Contains the serialized message along with the sender's public key and signature.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    /// The public key of the sender.
    sender_public_key: VerifyingKey,

    /// The signature of the message.
    signature: Signature,

    /// The serialized message.
    message: Vec<u8>,
}

impl Envelope {
    /// Authenticate and deserialize the message.
    fn authenticate_and_deserialize(self) -> Result<(VerifyingKey, Message), Error> {
        let Envelope {
            sender_public_key,
            signature,
            message,
        } = self;

        sender_public_key.verify_strict(&message, &signature)?;

        let message = bincode::deserialize(&message).map_err(Error::Deserialization)?;

        Ok((sender_public_key, message))
    }

    /// Serialize and sign a message.
    fn serialize_and_sign(message: &Message, signing_key: &SigningKey) -> Result<Self, Error> {
        let message = bincode::serialize(message).map_err(Error::Serialization)?;

        Ok(Self {
            sender_public_key: signing_key.verifying_key(),
            signature: signing_key.sign(&message),
            message,
        })
    }
}

// TODO: use for all errors in this module
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to authenticate a message")]
    Authentication(#[from] ed25519_dalek::SignatureError),

    #[error("failed to deserialize a message")]
    Deserialization(#[source] bincode::Error),

    #[error("failed to serialize a message")]
    Serialization(#[source] bincode::Error),
}
