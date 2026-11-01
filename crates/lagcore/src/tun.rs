//! Linux TUN device, used by the exit relay and the Linux client.
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    pub name: String,
}

impl Tun {
    pub fn create(name: &str) -> Result<Tun> {
        if name.len() >= libc::IFNAMSIZ {
            bail!("interface name too long: {name}");
        }
        let path = CString::new("/dev/net/tun")?;
        // SAFETY: path is a valid NUL-terminated string.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("open /dev/net/tun (needs root or CAP_NET_ADMIN)");
        }
        // SAFETY: raw is a fresh descriptor that nothing else owns.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut req = IfReq { name: [0; libc::IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
        for (d, s) in req.name.iter_mut().zip(name.bytes()) {
            *d = s as libc::c_char;
        }
        // SAFETY: req is a correctly sized ifreq that outlives the call.
        if unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF as _, &mut req) } < 0 {
            return Err(std::io::Error::last_os_error()).context("TUNSETIFF");
        }
        // SAFETY: the descriptor is owned by the AsyncFd for its whole lifetime
        // and is only closed after AsyncFd deregisters it on drop.
        let fd = unsafe { AsyncFd::register(owned) }.map_err(|e| anyhow::anyhow!("register tun fd: {e}"))?;
        Ok(Tun { fd, name: name.to_string() })
    }

    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut g = self.fd.readable().await?;
            let r = g.try_io(|f| {
                // SAFETY: buf is valid for writes of buf.len() bytes.
                let n = unsafe { libc::read(f.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            if let Ok(r) = r {
                return r;
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut g = self.fd.writable().await?;
            let r = g.try_io(|f| {
                // SAFETY: buf is valid for reads of buf.len() bytes.
                let n = unsafe { libc::write(f.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            if let Ok(r) = r {
                return r;
            }
        }
    }
}
