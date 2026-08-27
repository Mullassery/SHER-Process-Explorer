use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Unix,
}

/// TCP connection state, from `/proc/net/tcp{,6}`'s hex `st` field. Not
/// meaningful for UDP/Unix sockets, which report `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl ConnectionState {
    /// Parses the hex `st` field used by `/proc/net/tcp{,6}`.
    pub fn from_proc_hex(value: u8) -> Self {
        match value {
            0x01 => Self::Established,
            0x02 => Self::SynSent,
            0x03 => Self::SynRecv,
            0x04 => Self::FinWait1,
            0x05 => Self::FinWait2,
            0x06 => Self::TimeWait,
            0x07 => Self::Close,
            0x08 => Self::CloseWait,
            0x09 => Self::LastAck,
            0x0A => Self::Listen,
            0x0B => Self::Closing,
            _ => Self::Unknown,
        }
    }
}

/// One network connection or listening socket owned by a process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: Protocol,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: ConnectionState,
    /// Socket inode, used to resolve which process owns this connection by
    /// cross-referencing each process's `fd/*` socket symlinks.
    pub inode: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_from_proc_hex_covers_common_values() {
        assert_eq!(
            ConnectionState::from_proc_hex(0x01),
            ConnectionState::Established
        );
        assert_eq!(
            ConnectionState::from_proc_hex(0x0A),
            ConnectionState::Listen
        );
        assert_eq!(
            ConnectionState::from_proc_hex(0xFF),
            ConnectionState::Unknown
        );
    }

    #[test]
    fn network_connection_json_round_trip() {
        let conn = NetworkConnection {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:8080".into(),
            remote_addr: "10.0.0.5:443".into(),
            state: ConnectionState::Established,
            inode: 123_456,
        };
        let json = serde_json::to_string(&conn).unwrap();
        let back: NetworkConnection = serde_json::from_str(&json).unwrap();
        assert_eq!(conn, back);
    }
}
