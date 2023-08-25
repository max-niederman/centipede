use std::{
    ffi::{CStr, CString},
    io::{self, Read, Write},
    mem,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use cidr::{IpCidr, IpInet};

pub struct Device {
    name: CString,
    queue: OwnedFd,
    ctl: OwnedFd,
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.queue.as_raw_fd()
    }
}

impl Device {
    pub fn new(name: Option<CString>) -> io::Result<Self> {
        let name = name.unwrap_or_default();
        if name.as_bytes_with_nul().len() > libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }

        let fd = unsafe {
            OwnedFd::from_raw_fd(libc::open(b"/dev/net/tun\0".as_ptr().cast(), libc::O_RDWR))
        };
        if fd.as_raw_fd() < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };

        ifr.ifr_name[..name.as_bytes().len()].copy_from_slice(bytes_to_signed(name.as_bytes()));

        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

        unsafe {
            if libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &ifr) < 0 {
                libc::close(fd.as_raw_fd());
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self::from_raw_fd(fd, name))
    }

    pub fn from_raw_fd(fd: OwnedFd, name: CString) -> Self {
        let ctl = unsafe { OwnedFd::from_raw_fd(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)) };

        Self {
            queue: fd,
            ctl,
            name,
        }
    }

    fn request(&self) -> libc::ifreq {
        let mut req: libc::ifreq = unsafe { mem::zeroed() };

        unsafe {
            req.ifr_name[..self.name.as_bytes().len()]
                .copy_from_slice(bytes_to_signed(self.name.as_bytes()));
        }

        req
    }

    pub fn bring_up(&self) -> io::Result<()> {
        unsafe {
            let mut ifr = self.request();

            if libc::ioctl(self.ctl.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) < 0 {
                return Err(io::Error::last_os_error());
            }

            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;

            if libc::ioctl(self.ctl.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn set_address(&self, address: IpAddr) -> io::Result<()> {
        let mut ifr = self.request();

        ifr.ifr_ifru.ifru_addr = ip_to_sockaddr(address);

        unsafe {
            if libc::ioctl(self.ctl.as_raw_fd(), libc::SIOCSIFADDR, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn set_netmask(&self, network: IpCidr) -> io::Result<()> {
        let mut ifr = self.request();

        ifr.ifr_ifru.ifru_addr = ip_to_sockaddr(network.mask());

        unsafe {
            if libc::ioctl(self.ctl.as_raw_fd(), libc::SIOCSIFNETMASK, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn handle(&self) -> DeviceHandle<'_> {
        DeviceHandle(self)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.queue.as_raw_fd());
            libc::close(self.ctl.as_raw_fd());
        }
    }
}

pub struct DeviceHandle<'a>(&'a Device);

impl<'a> Read for DeviceHandle<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let n = libc::read(self.0.queue.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len());
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }
}

impl<'a> Write for DeviceHandle<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let n = libc::write(self.0.queue.as_raw_fd(), buf.as_ptr().cast(), buf.len());
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bytes_to_signed(val: &[u8]) -> &[i8] {
    unsafe { mem::transmute(val) }
}

fn ip_to_sockaddr(addr: IpAddr) -> libc::sockaddr {
    unsafe {
        match addr {
            IpAddr::V4(addr) => mem::transmute(libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.octets()),
                },
                sin_zero: [0; 8],
            }),
            IpAddr::V6(addr) => todo!(),
        }
    }
}

const TUNSETIFF: libc::c_ulong = ioctl_sys::iow!(b'T', 202, mem::size_of::<libc::c_int>()) as _;
