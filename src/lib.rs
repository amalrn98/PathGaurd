//! # PathGuard
//!
//! An experimental, decoy-assisted, authenticated data transmission protocol.
//! The sender verifies the communication environment before it releases the
//! encrypted payload.
//!
//! Cryptographic endpoint authentication and authenticated encryption provide
//! the security guarantees. Decoys, canaries and multi-path checks add
//! detection signals on top of them. They are not a substitute.
//!
//! **Status: research prototype. Not audited. Do not use to protect real secrets.**
//!
//! ```
//! use pathguard::sim::{self, World};
//! use pathguard::Policy;
//!
//! let world = World::new();
//! let sender = world.sender(Policy::balanced());
//! let mut paths = vec![world.honest_path("p1", &["isp-a", "ix-1"], 1)];
//! let report = sender.send(b"hello", &mut paths).unwrap();
//! assert!(report.delivered);
//! assert_eq!(world.take_delivered(), vec![b"hello".to_vec()]);
//! # let _ = sim::PAYLOAD;
//! ```

#![deny(unsafe_code)]

pub mod canary;
pub mod canary_service;
pub mod clock;
pub mod codec;
pub mod crypto;
pub mod detect;
pub mod error;
pub mod handshake;
pub mod limits;
pub mod message;
pub mod multipath;
pub mod path;
pub mod policy;
pub mod receiver;
pub mod sender;
pub mod sim;
pub mod util;

pub use crypto::{Identity, PublicIdentity};
pub use error::{Error, Result};
pub use path::{Path, PathError, PathResponse};
pub use policy::Policy;
pub use receiver::{Receiver, ReceiverConfig, ReceiverStats, SenderPolicy};
pub use sender::{CanaryStatus, LateCanaryEvent, SendError, SendReport, Sender};
