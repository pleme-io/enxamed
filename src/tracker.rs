//! Minimal HTTP tracker announce ([BEP-3] tracker protocol).
//!
//! Kept dependency-light + in-style: a hand-rolled `GET` over a tokio
//! socket and a `bencode`-typed response parse, rather than pulling a
//! full HTTP/TLS stack for one request. `http://` trackers only — the
//! `https`/UDP ([BEP-15]) variants are a documented follow-up.
//!
//! [BEP-3]: https://www.bittorrent.org/beps/bep_0003.html
//! [BEP-15]: https://www.bittorrent.org/beps/bep_0015.html

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail};
use bencode::Bencode;
use enxame_metainfo::InfoHash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Announce to an `http://` tracker and return the peer addresses it
/// reports (compact or list form).
pub async fn announce(
    announce_url: &str,
    info_hash: InfoHash,
    peer_id: [u8; 20],
    port: u16,
    left: u64,
) -> Result<Vec<SocketAddr>> {
    let url = announce_url
        .strip_prefix("http://")
        .context("only http:// trackers are supported in this MVP")?;
    let (host_port, path) = url.split_once('/').map_or((url, "/"), |(h, p)| (h, p));
    let (host, host_port_num) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (host_port, 80),
    };

    // Build the query string with percent-encoded binary fields.
    let mut query = String::new();
    query.push('/');
    query.push_str(path.trim_start_matches('/'));
    query.push(if path.contains('?') { '&' } else { '?' });
    query.push_str("info_hash=");
    percent_encode_into(&mut query, &info_hash.0);
    query.push_str("&peer_id=");
    percent_encode_into(&mut query, &peer_id);
    query.push_str("&port=");
    push_u64(&mut query, u64::from(port));
    query.push_str("&uploaded=0&downloaded=0&left=");
    push_u64(&mut query, left);
    query.push_str("&compact=1&event=started");

    // One HTTP/1.0 request (no keep-alive → the server closes, EOF frames
    // the response for us).
    let mut request = String::with_capacity(query.len() + host.len() + 64);
    request.push_str("GET ");
    request.push_str(&query);
    request.push_str(" HTTP/1.0\r\nHost: ");
    request.push_str(host);
    request.push_str("\r\nUser-Agent: enxame/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n");

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        TcpStream::connect((host, host_port_num)),
    )
    .await
    .context("tracker connect timeout")??;
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    // Split headers from the bencoded body at the blank line.
    let body = split_http_body(&response).context("malformed tracker HTTP response")?;
    parse_peers(body)
}

/// Parse the bencoded tracker response body into peer addresses.
fn parse_peers(body: &[u8]) -> Result<Vec<SocketAddr>> {
    let value = bencode::parse(body).map_err(|e| anyhow::anyhow!("tracker bencode: {e}"))?;
    if let Some(reason) = value.get(b"failure reason").and_then(Bencode::as_str) {
        bail!("tracker failure: {reason}");
    }
    let peers = value.get(b"peers").context("tracker response has no `peers`")?;
    match peers {
        // Compact form: 6 bytes per peer (4 IPv4 + 2 port, big-endian).
        Bencode::Bytes(b) => Ok(b
            .chunks_exact(6)
            .map(|c| {
                let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
                let port = u16::from(c[4]) << 8 | u16::from(c[5]);
                SocketAddr::from((ip, port))
            })
            .collect()),
        // Dictionary list form.
        Bencode::List(list) => Ok(list
            .iter()
            .filter_map(|p| {
                let ip = p.get(b"ip").and_then(Bencode::as_str)?;
                let port = u16::try_from(p.get(b"port").and_then(Bencode::as_int)?).ok()?;
                let ip: std::net::IpAddr = ip.parse().ok()?;
                Some(SocketAddr::new(ip, port))
            })
            .collect()),
        _ => bail!("tracker `peers` is neither compact bytes nor a list"),
    }
}

/// Return the body bytes after the `\r\n\r\n` header terminator.
fn split_http_body(response: &[u8]) -> Option<&[u8]> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &response[i + 4..])
}

/// Percent-encode bytes per the tracker spec: unreserved bytes pass
/// through, everything else becomes `%XX`.
fn percent_encode_into(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
}

fn push_u64(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + u8::try_from(n % 10).expect("digit");
        n /= 10;
    }
    out.push_str(std::str::from_utf8(&buf[i..]).expect("ascii digits"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_peers() {
        // d5:peers6:<1.2.3.4:6881>e
        let mut body = Vec::new();
        body.extend_from_slice(b"d5:peers6:");
        body.extend_from_slice(&[1, 2, 3, 4, 0x1a, 0xe1]); // 6881 = 0x1ae1
        body.push(b'e');
        let peers = parse_peers(&body).unwrap();
        assert_eq!(peers, vec!["1.2.3.4:6881".parse().unwrap()]);
    }

    #[test]
    fn surfaces_tracker_failure() {
        let err = parse_peers(b"d14:failure reason4:nopee").unwrap_err();
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn percent_encodes_binary() {
        let mut s = String::new();
        percent_encode_into(&mut s, &[0x00, 0xff, b'A', b'-']);
        assert_eq!(s, "%00%FFA-");
    }

    #[test]
    fn splits_http_body() {
        assert_eq!(split_http_body(b"HTTP/1.0 200 OK\r\n\r\nbody"), Some(b"body".as_slice()));
    }
}
