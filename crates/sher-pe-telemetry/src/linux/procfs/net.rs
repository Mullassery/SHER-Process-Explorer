use std::net::Ipv6Addr;
use std::path::Path;

use sher_pe_model::{ConnectionState, NetworkConnection, Pid, Protocol};

use super::common::{parse_err, read_to_string_optional};
use super::files::socket_inodes;
use crate::Result;

/// Every connection/listening socket owned by `pid`, resolved by reading
/// each of `/proc/[pid]/net/{tcp,tcp6,udp,udp6,unix}` (per-pid so this is
/// correct even inside a network namespace) and keeping only the rows
/// whose inode appears among the process's own `fd/*` sockets.
pub fn read_connections(root: &Path, pid: Pid) -> Result<Vec<NetworkConnection>> {
    let owned_inodes = socket_inodes(root, pid)?;
    let net_dir = root.join(pid.to_string()).join("net");

    let mut connections = Vec::new();
    for (file_name, protocol) in [
        ("tcp", Protocol::Tcp),
        ("tcp6", Protocol::Tcp6),
        ("udp", Protocol::Udp),
        ("udp6", Protocol::Udp6),
    ] {
        let path = net_dir.join(file_name);
        let Some(content) = read_to_string_optional(&path)? else {
            continue;
        };
        connections.extend(
            parse_tcp_udp(&content, protocol, &path)?
                .into_iter()
                .filter(|conn| owned_inodes.contains(&conn.inode)),
        );
    }

    let unix_path = net_dir.join("unix");
    if let Some(content) = read_to_string_optional(&unix_path)? {
        connections.extend(
            parse_unix(&content)
                .into_iter()
                .filter(|conn| owned_inodes.contains(&conn.inode)),
        );
    }

    Ok(connections)
}

/// Parses `/proc/[pid]/net/{tcp,tcp6,udp,udp6}` — a header line followed
/// by one row per socket. Column layout (0-indexed after
/// whitespace-splitting): `sl local_address rem_address st tx:rx tr:tm
/// retrnsmt uid timeout inode ...`.
fn parse_tcp_udp(content: &str, protocol: Protocol, path: &Path) -> Result<Vec<NetworkConnection>> {
    let mut connections = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue; // blank trailing line, not a malformed one worth erroring on
        }
        let (local_addr, _) = decode_hex_addr_port(fields[1], path)?;
        let (remote_addr, _) = decode_hex_addr_port(fields[2], path)?;
        let state_byte = u8::from_str_radix(fields[3], 16)
            .map_err(|_| parse_err(path, format!("bad state hex '{}'", fields[3])))?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|_| parse_err(path, format!("bad inode '{}'", fields[9])))?;
        connections.push(NetworkConnection {
            protocol,
            local_addr,
            remote_addr,
            state: ConnectionState::from_proc_hex(state_byte),
            inode,
        });
    }
    Ok(connections)
}

/// Parses `/proc/[pid]/net/unix`. Path is optional (anonymous/unbound
/// sockets have none); state isn't meaningful for these, so it's always
/// `Unknown`.
fn parse_unix(content: &str) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let Ok(inode) = fields[6].parse::<u64>() else {
            continue;
        };
        let path = fields.get(7).map(|s| s.to_string()).unwrap_or_default();
        connections.push(NetworkConnection {
            protocol: Protocol::Unix,
            local_addr: path,
            remote_addr: String::new(),
            state: ConnectionState::Unknown,
            inode,
        });
    }
    connections
}

/// Decodes a `"HEXADDR:HEXPORT"` field into `("ip:port", port)`. The
/// kernel stores each 32-bit address word byte-reversed from the dotted/
/// colon-separated form, so a naive left-to-right hex decode produces the
/// wrong address.
fn decode_hex_addr_port(field: &str, path: &Path) -> Result<(String, u16)> {
    let (addr_hex, port_hex) = field
        .split_once(':')
        .ok_or_else(|| parse_err(path, format!("expected 'addr:port', got '{field}'")))?;
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|_| parse_err(path, format!("bad port hex '{port_hex}'")))?;
    let addr = decode_hex_addr(addr_hex, path)?;
    Ok((format!("{addr}:{port}"), port))
}

fn decode_hex_addr(hex: &str, path: &Path) -> Result<String> {
    let bytes: Result<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| parse_err(path, format!("bad address hex '{hex}'")))
        })
        .collect();
    let bytes = bytes?;

    match bytes.len() {
        4 => {
            let mut b = bytes;
            b.reverse();
            Ok(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }
        16 => {
            // Each 4-byte (32-bit) word is stored byte-reversed
            // independently; words are not reversed relative to each other.
            let mut out = [0u8; 16];
            for word in 0..4 {
                for k in 0..4 {
                    out[word * 4 + k] = bytes[word * 4 + (3 - k)];
                }
            }
            Ok(Ipv6Addr::from(out).to_string())
        }
        _ => Err(parse_err(
            path,
            format!("unexpected address length in '{hex}'"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn decode_hex_addr_port_decodes_ipv4() {
        let (addr, port) = decode_hex_addr_port("0100007F:1F90", Path::new("test")).unwrap();
        assert_eq!(addr, "127.0.0.1:8080");
        assert_eq!(port, 8080);
    }

    #[test]
    fn decode_hex_addr_port_decodes_ipv6_loopback() {
        let (addr, _) =
            decode_hex_addr_port("00000000000000000000000001000000:1F90", Path::new("test"))
                .unwrap();
        assert!(addr.starts_with("::1:8080") || addr.contains("::1"));
    }

    #[test]
    fn parse_tcp_udp_skips_header_and_reads_inode() {
        let content = "header\n   0: 0100007F:1F90 0A00000A:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 100 0 0 10 0\n";
        let conns = parse_tcp_udp(content, Protocol::Tcp, Path::new("test")).unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].inode, 999);
        assert_eq!(conns[0].local_addr, "127.0.0.1:8080");
        assert_eq!(conns[0].remote_addr, "10.0.0.10:443");
        assert_eq!(conns[0].state, ConnectionState::Established);
    }

    #[test]
    fn parse_unix_reads_path_and_inode() {
        let content =
            "header\n0000000000000000: 00000002 00000000 00010000 0001 01 3000 /run/sherd.sock\n";
        let conns = parse_unix(content);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].inode, 3000);
        assert_eq!(conns[0].local_addr, "/run/sherd.sock");
        assert_eq!(conns[0].protocol, Protocol::Unix);
    }

    #[test]
    fn read_connections_filters_to_pid_owned_sockets_only() {
        // pid 100's fd table only owns inodes 999 (tcp), 1500 (tcp6), and
        // 3000 (unix) — the udp fixture row (inode 2000) must be excluded
        // since no fd in pid 100 references it.
        let conns = read_connections(&fixture_root(), 100).unwrap();
        let inodes: std::collections::HashSet<u64> = conns.iter().map(|c| c.inode).collect();
        assert_eq!(inodes, std::collections::HashSet::from([999, 1500, 3000]));
    }
}
