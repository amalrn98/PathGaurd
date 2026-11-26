//! Transport abstraction.
//!
//! A `Path` is one network route to the receiver with request/response
//! semantics. Implement it for real sockets, or use the simulator in `sim`.

use std::time::Duration;

/// Everything the path returned for one request.
pub struct PathResponse {
    /// Reply datagrams received. More than one means duplication.
    pub replies: Vec<Vec<u8>>,
    /// Round-trip time.
    pub rtt: Duration,
}

/// Transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// No answer within the deadline.
    Timeout,
    /// The path is closed.
    Closed,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::Timeout => write!(f, "timeout"),
            PathError::Closed => write!(f, "path closed"),
        }
    }
}

/// One route to the receiver.
pub trait Path {
    /// Stable identifier used in reports.
    fn id(&self) -> &str;
    /// Infrastructure identifiers on the route (ASNs, router ids). Used only
    /// for diversity scoring. May be empty if unknown.
    fn hops(&self) -> &[String];
    /// Send one request and collect the reply.
    fn exchange(&mut self, request: &[u8]) -> Result<PathResponse, PathError>;
}
