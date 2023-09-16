#![feature(iterator_try_collect)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(never_type)]
#![feature(split_array)]

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

pub mod config;
pub mod control;
pub mod tunnel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct EndpointId(pub NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct TunnelId(pub NonZeroU32);
