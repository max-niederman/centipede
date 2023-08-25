use std::os::fd::OwnedFd;

pub struct Device {
    fd: OwnedFd,
}

