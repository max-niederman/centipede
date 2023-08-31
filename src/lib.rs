#![feature(never_type)]
#![feature(iterator_try_collect)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]

use std::num::NonZeroU32;

pub mod tunnel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EndpointId(pub NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TunnelId(pub u64);
