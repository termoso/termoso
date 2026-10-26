//! Wake-on-LAN: the magic packet (6 × 0xFF + 16 × MAC) sent over UDP to the
//! broadcast address, port 9, from every local interface. Works only on the
//! same L2 segment (or via a router that forwards directed broadcasts), which
//! is why the host record stores the MAC and the user is told what was sent.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::{CoreError, Result};

/// Parse `aa:bb:cc:dd:ee:ff`, `aa-bb-…`, `aabb.ccdd.eeff` or `aabbccddeeff`.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let hex: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreError::Invalid(format!("not a MAC address: {s}")));
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    Ok(mac)
}

/// The 102-byte magic packet for `mac`.
pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&mac);
    }
    p
}

/// Send the magic packet for `mac` to `broadcast` (default 255.255.255.255)
/// on ports 9 and 7. Returns how many datagrams went out.
pub async fn wake(mac: &str, broadcast: Option<IpAddr>) -> Result<usize> {
    let mac = parse_mac(mac)?;
    let packet = magic_packet(mac);
    let target = broadcast.unwrap_or(IpAddr::V4(Ipv4Addr::BROADCAST));
    let bind: SocketAddr = match target {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.set_broadcast(true)?;
    let mut sent = 0;
    for port in [9u16, 7] {
        if sock
            .send_to(&packet, SocketAddr::new(target, port))
            .await
            .is_ok()
        {
            sent += 1;
        }
    }
    if sent == 0 {
        return Err(CoreError::Invalid("could not send the magic packet".into()));
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formats() {
        let m = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff").unwrap(), m);
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF").unwrap(), m);
        assert_eq!(parse_mac("aabb.ccdd.eeff").unwrap(), m);
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_err());
        let p = magic_packet(m);
        assert_eq!(p.len(), 102);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[6..12], &m);
        assert_eq!(&p[96..], &m);
    }
}
