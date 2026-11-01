//! Minimal runtime binding to WinDivert 2.x. Loaded with LoadLibrary so a
//! missing DLL produces a helpful error rather than a process-start failure.
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{c_void, CString};

/// Layout from windivert.h v2.2: i64 timestamp, u32 bitfield, u32 reserved,
/// and a 64-byte union whose NETWORK member starts with IfIdx and SubIfIdx.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub bits: u32,
    pub reserved: u32,
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub rest: [u8; 56],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

const BIT_IPV6: u32 = 1 << 20;
const BIT_IP_CHECKSUM: u32 = 1 << 21;
const BIT_TCP_CHECKSUM: u32 = 1 << 22;
const BIT_UDP_CHECKSUM: u32 = 1 << 23;

impl Address {
    pub fn is_ipv6(&self) -> bool {
        self.bits & BIT_IPV6 != 0
    }

    /// An inbound network-layer address on the given interface whose checksums
    /// are all marked valid, because lagcore::ip has already computed them.
    pub fn inbound(if_idx: u32, sub_if_idx: u32) -> Address {
        Address {
            timestamp: 0,
            bits: BIT_IP_CHECKSUM | BIT_TCP_CHECKSUM | BIT_UDP_CHECKSUM,
            reserved: 0,
            if_idx,
            sub_if_idx,
            rest: [0; 56],
        }
    }
}

const LAYER_NETWORK: i32 = 0;
const FLAG_FRAGMENTS: u64 = 0x0020;
const INVALID_HANDLE: isize = -1;

type OpenFn = unsafe extern "C" fn(*const std::ffi::c_char, i32, i16, u64) -> *mut c_void;
type RecvFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(*mut c_void, *const c_void, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "C" fn(*mut c_void) -> i32;
type ShutdownFn = unsafe extern "C" fn(*mut c_void, i32) -> i32;

const SHUTDOWN_BOTH: i32 = 3;
/// WINDIVERT_MTU_MAX: 40 + 0xFFFF. A smaller buffer makes Recv fail on large packets.
pub const MTU_MAX: usize = 40 + 0xFFFF;
/// Recv reports this once the handle has been shut down and drained.
pub const ERROR_NO_DATA: i32 = 232;
pub const ERROR_INVALID_HANDLE: i32 = 6;

pub struct Handle {
    raw: *mut c_void,
    recv: RecvFn,
    send: SendFn,
    close: CloseFn,
    shutdown: ShutdownFn,
    _lib: libloading::Library,
}

// SAFETY: WinDivert handles are documented as usable for concurrent Recv and
// Send from multiple threads, and the function pointers are immutable.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

fn explain_open_error(code: i32) -> String {
    match code {
        5 => "access denied. Run the terminal as Administrator.".into(),
        2 => "WinDivert64.sys not found. Keep it next to lagrelay.exe.".into(),
        577 => "driver signature rejected. Windows or a security tool refused WinDivert's driver.".into(),
        654 => "an older WinDivert driver is loaded by another program. Close it, or reboot.".into(),
        1058 | 1275 => "the driver was blocked (often by anti-cheat, antivirus or Core Isolation policy).".into(),
        87 => "invalid filter (this is a LagRelay bug; please report it).".into(),
        c => format!("Windows error {c}"),
    }
}

/// Asks the real WinDivert DLL to compile a filter, without loading the driver.
pub fn validate_filter(filter: &str) -> Result<()> {
    type CompileFn = unsafe extern "C" fn(*const std::ffi::c_char, i32, *mut std::ffi::c_char, u32, *mut *const std::ffi::c_char, *mut u32) -> i32;
    let dll = std::env::current_exe()?.parent().context("locate executable")?.join("WinDivert.dll");
    // SAFETY: as in Handle::open; the signature is transcribed from windivert.h.
    unsafe {
        let lib = libloading::Library::new(&dll)?;
        let compile = *lib.get::<CompileFn>(b"WinDivertHelperCompileFilter\0")?;
        let f = CString::new(filter)?;
        let (mut err, mut pos) = (std::ptr::null(), 0u32);
        if compile(f.as_ptr(), LAYER_NETWORK, std::ptr::null_mut(), 0, &mut err, &mut pos) == 0 {
            let msg = if err.is_null() { "unknown error".into() } else { std::ffi::CStr::from_ptr(err).to_string_lossy() };
            bail!("{msg} at position {pos} of: {filter}");
        }
    }
    Ok(())
}

impl Handle {
    pub fn open(filter: &str) -> Result<Handle> {
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).context("locate executable")?;
        let dll = exe_dir.join("WinDivert.dll");
        // SAFETY: loading the WinDivert DLL shipped beside the executable, by
        // absolute path so that the DLL search order cannot substitute another.
        let lib = unsafe { libloading::Library::new(&dll) }.map_err(|e| anyhow!("load {}: {e}. Run scripts/fetch-windivert.ps1 or reinstall.", dll.display()))?;
        // SAFETY: signatures are transcribed from windivert.h v2.2.
        let (open, recv, send, close, shutdown) = unsafe {
            (
                *lib.get::<OpenFn>(b"WinDivertOpen\0")?,
                *lib.get::<RecvFn>(b"WinDivertRecv\0")?,
                *lib.get::<SendFn>(b"WinDivertSend\0")?,
                *lib.get::<CloseFn>(b"WinDivertClose\0")?,
                *lib.get::<ShutdownFn>(b"WinDivertShutdown\0")?,
            )
        };
        let f = CString::new(filter)?;
        // SAFETY: f is a valid C string that outlives the call.
        let raw = unsafe { open(f.as_ptr(), LAYER_NETWORK, 0, FLAG_FRAGMENTS) };
        if raw as isize == INVALID_HANDLE || raw.is_null() {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            bail!("WinDivert could not start: {}", explain_open_error(code));
        }
        Ok(Handle { raw, recv, send, close, shutdown, _lib: lib })
    }

    /// Stops diverting traffic and wakes any thread blocked in `recv`.
    pub fn shutdown(&self) {
        // SAFETY: raw stays valid until Drop, which needs every Arc gone.
        unsafe { (self.shutdown)(self.raw, SHUTDOWN_BOTH) };
    }

    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Address)> {
        let mut n = 0u32;
        let mut addr = std::mem::MaybeUninit::<Address>::zeroed();
        // SAFETY: buf and addr are valid for the lengths passed to the driver.
        let ok = unsafe { (self.recv)(self.raw, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, addr.as_mut_ptr()) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: zero-initialised, and every bit pattern is valid for Address.
        Ok((n as usize, unsafe { addr.assume_init() }))
    }

    pub fn send(&self, packet: &[u8], addr: &Address) -> Result<()> {
        // SAFETY: packet and addr are valid for the duration of the call.
        let ok = unsafe { (self.send)(self.raw, packet.as_ptr().cast(), packet.len() as u32, std::ptr::null_mut(), addr) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: raw is a live handle and this is its only close.
        unsafe { (self.close)(self.raw) };
    }
}
