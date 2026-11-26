//! Wire messages.

use crate::codec::{Reader, Writer, MAX_MESSAGE};
use crate::error::{Error, Result};

/// Session identifier.
pub type SessionId = [u8; 16];
/// Probe identifier.
pub type ProbeId = [u8; 16];

/// Tag byte of each message type.
pub const TAG_HELLO: u8 = 1;
/// Tag byte of the hello acknowledgement.
pub const TAG_HELLO_ACK: u8 = 2;
/// Tag byte of a probe.
pub const TAG_PROBE: u8 = 3;
/// Tag byte of a probe reply.
pub const TAG_PROBE_REPLY: u8 = 4;
/// Tag byte of the payload message.
pub const TAG_PAYLOAD: u8 = 5;
/// Tag byte of the payload acknowledgement.
pub const TAG_PAYLOAD_ACK: u8 = 6;
/// Tag byte of the session close message.
pub const TAG_CLOSE: u8 = 7;
/// Tag byte of a rejection.
pub const TAG_REJECT: u8 = 8;

/// Kind of probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeKind {
    /// Plain probe with a unique nonce. Detects tampering, duplication and redirection.
    Interception = 0,
    /// Plaintext bait that looks like a credential and embeds a canary token.
    Bait = 1,
    /// Encrypted, payload-shaped decoy. Carries no real data or key material.
    PayloadLike = 2,
}

impl ProbeKind {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Interception),
            1 => Ok(Self::Bait),
            2 => Ok(Self::PayloadLike),
            _ => Err(Error::Malformed("unknown probe kind")),
        }
    }
}

/// Reason a receiver rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectCode {
    /// The request could not be parsed.
    BadRequest = 1,
    /// No such session.
    UnknownSession = 2,
    /// Signature, MAC or decryption failed.
    AuthFailed = 3,
    /// Replay or duplicate detected.
    Replay = 4,
    /// Receiver is at capacity.
    Busy = 5,
}

impl RejectCode {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::BadRequest),
            2 => Ok(Self::UnknownSession),
            3 => Ok(Self::AuthFailed),
            4 => Ok(Self::Replay),
            5 => Ok(Self::Busy),
            _ => Err(Error::Malformed("unknown reject code")),
        }
    }
}

/// A PathGuard wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Sender hello: ephemeral key, identity, named recipient, signature.
    Hello {
        /// Session id chosen by the sender.
        session_id: SessionId,
        /// Sender ephemeral X25519 key.
        sender_eph: [u8; 32],
        /// Sender Ed25519 identity.
        sender_id: [u8; 32],
        /// Identity of the intended receiver.
        recipient: [u8; 32],
        /// Signature over the hello input.
        sig: [u8; 64],
    },
    /// Receiver acknowledgement with its ephemeral key and signature.
    HelloAck {
        /// Session id echoed back.
        session_id: SessionId,
        /// Receiver ephemeral X25519 key.
        recv_eph: [u8; 32],
        /// Receiver Ed25519 identity.
        recv_id: [u8; 32],
        /// Signature over the ack input.
        sig: [u8; 64],
    },
    /// Verification probe.
    Probe {
        /// Session id.
        session_id: SessionId,
        /// Unique probe id.
        probe_id: ProbeId,
        /// Probe kind.
        kind: ProbeKind,
        /// Probe sequence number.
        seq: u64,
        /// Probe body.
        body: Vec<u8>,
        /// MAC under the probe key.
        mac: [u8; 32],
    },
    /// Authenticated reply to a probe.
    ProbeReply {
        /// Session id.
        session_id: SessionId,
        /// Probe id.
        probe_id: ProbeId,
        /// Probe sequence number.
        seq: u64,
        /// MAC proving the receiver holds the session keys.
        mac: [u8; 32],
    },
    /// The encrypted payload.
    Payload {
        /// Session id.
        session_id: SessionId,
        /// Payload sequence number (strictly increasing).
        seq: u64,
        /// AEAD ciphertext.
        ciphertext: Vec<u8>,
    },
    /// Authenticated acknowledgement of a payload.
    PayloadAck {
        /// Session id.
        session_id: SessionId,
        /// Payload sequence number.
        seq: u64,
        /// MAC over the ciphertext digest.
        mac: [u8; 32],
    },
    /// Authenticated request to drop a session and its keys.
    Close {
        /// Session id.
        session_id: SessionId,
        /// MAC under the probe key.
        mac: [u8; 32],
    },
    /// Rejection.
    Reject {
        /// Reason.
        code: RejectCode,
    },
}

impl Message {
    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Message::Hello { session_id, sender_eph, sender_id, recipient, sig } => {
                w.u8(TAG_HELLO);
                w.raw(session_id);
                w.raw(sender_eph);
                w.raw(sender_id);
                w.raw(recipient);
                w.raw(sig);
            }
            Message::HelloAck { session_id, recv_eph, recv_id, sig } => {
                w.u8(TAG_HELLO_ACK);
                w.raw(session_id);
                w.raw(recv_eph);
                w.raw(recv_id);
                w.raw(sig);
            }
            Message::Probe { session_id, probe_id, kind, seq, body, mac } => {
                w.u8(TAG_PROBE);
                w.raw(session_id);
                w.raw(probe_id);
                w.u8(*kind as u8);
                w.u64(*seq);
                w.bytes(body);
                w.raw(mac);
            }
            Message::ProbeReply { session_id, probe_id, seq, mac } => {
                w.u8(TAG_PROBE_REPLY);
                w.raw(session_id);
                w.raw(probe_id);
                w.u64(*seq);
                w.raw(mac);
            }
            Message::Payload { session_id, seq, ciphertext } => {
                w.u8(TAG_PAYLOAD);
                w.raw(session_id);
                w.u64(*seq);
                w.bytes(ciphertext);
            }
            Message::PayloadAck { session_id, seq, mac } => {
                w.u8(TAG_PAYLOAD_ACK);
                w.raw(session_id);
                w.u64(*seq);
                w.raw(mac);
            }
            Message::Close { session_id, mac } => {
                w.u8(TAG_CLOSE);
                w.raw(session_id);
                w.raw(mac);
            }
            Message::Reject { code } => {
                w.u8(TAG_REJECT);
                w.u8(*code as u8);
            }
        }
        w.finish()
    }

    /// Decode from bytes. Never panics on arbitrary input.
    pub fn decode(buf: &[u8]) -> Result<Message> {
        if buf.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        let mut r = Reader::new(buf);
        let msg = match r.u8()? {
            TAG_HELLO => Message::Hello {
                session_id: r.array()?,
                sender_eph: r.array()?,
                sender_id: r.array()?,
                recipient: r.array()?,
                sig: r.array()?,
            },
            TAG_HELLO_ACK => Message::HelloAck {
                session_id: r.array()?,
                recv_eph: r.array()?,
                recv_id: r.array()?,
                sig: r.array()?,
            },
            TAG_PROBE => Message::Probe {
                session_id: r.array()?,
                probe_id: r.array()?,
                kind: ProbeKind::from_u8(r.u8()?)?,
                seq: r.u64()?,
                body: r.bytes()?,
                mac: r.array()?,
            },
            TAG_PROBE_REPLY => Message::ProbeReply {
                session_id: r.array()?,
                probe_id: r.array()?,
                seq: r.u64()?,
                mac: r.array()?,
            },
            TAG_PAYLOAD => Message::Payload {
                session_id: r.array()?,
                seq: r.u64()?,
                ciphertext: r.bytes()?,
            },
            TAG_PAYLOAD_ACK => Message::PayloadAck {
                session_id: r.array()?,
                seq: r.u64()?,
                mac: r.array()?,
            },
            TAG_CLOSE => Message::Close {
                session_id: r.array()?,
                mac: r.array()?,
            },
            TAG_REJECT => Message::Reject {
                code: RejectCode::from_u8(r.u8()?)?,
            },
            _ => return Err(Error::Malformed("unknown message tag")),
        };
        r.finish()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all() {
        let msgs = vec![
            Message::Hello { session_id: [1; 16], sender_eph: [2; 32], sender_id: [3; 32], recipient: [4; 32], sig: [5; 64] },
            Message::HelloAck { session_id: [1; 16], recv_eph: [2; 32], recv_id: [3; 32], sig: [5; 64] },
            Message::Probe { session_id: [1; 16], probe_id: [2; 16], kind: ProbeKind::Bait, seq: 9, body: vec![1, 2, 3], mac: [7; 32] },
            Message::ProbeReply { session_id: [1; 16], probe_id: [2; 16], seq: 9, mac: [7; 32] },
            Message::Payload { session_id: [1; 16], seq: 1, ciphertext: vec![9; 100] },
            Message::PayloadAck { session_id: [1; 16], seq: 1, mac: [7; 32] },
            Message::Close { session_id: [1; 16], mac: [7; 32] },
            Message::Reject { code: RejectCode::Replay },
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn decode_never_panics_on_garbage() {
        for len in 0..80usize {
            for fill in [0u8, 1, 3, 255] {
                let buf = vec![fill; len];
                let _ = Message::decode(&buf);
            }
        }
        assert!(Message::decode(&[3, 1, 2]).is_err());
    }
}
