//! Shared protocol core for the LagRelay client and relay daemon.
pub mod ip;
pub mod reliab;
pub mod route;
pub mod session;
pub mod wire;

#[cfg(target_os = "linux")]
pub mod tun;

/// Default inner MTU. Leaves room for up to two bridge hops of encapsulation
/// on a 1500-byte path (IP+UDP 28, plus ~38 bytes per encryption layer).
pub const TUNNEL_MTU: u16 = 1340;
/// TCP MSS for tunnelled flows: MTU minus 40 bytes of IPv4 and TCP headers.
pub const TUNNEL_MSS: u16 = TUNNEL_MTU - 40;
pub const DEFAULT_PORT: u16 = 41820;
