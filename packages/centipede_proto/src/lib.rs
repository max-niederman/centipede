pub mod auth;
pub mod control;
pub mod error;
pub mod packet;

// pub use control::Message as ControlMessage;
pub use packet::Message as PacketMessage;

mod seal {
    pub trait Sealed {}
}
