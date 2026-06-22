//! `enxamed` — the ENXAME BitTorrent daemon/client.
//!
//! A thin async (tokio) shell around the **sans-io** `enxame-engine`:
//! the engine is the tested brain (`(state, event) -> actions`); this
//! binary supplies the world — a tracker announce, TCP peer
//! connections, and disk. The clean split (sans-io core + I/O shell) is
//! the pleme-io idiom; it keeps the protocol logic unit-tested and the
//! networking a mechanical adapter.
//!
//! MVP scope: leech a single-file torrent from an `http://` tracker over
//! TCP peers. `https`/UDP trackers, uTP, multi-file mapping, DHT, and
//! seeding are the documented next phases (`theory/ENXAME.md` M4+).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use enxame_engine::{Action, Event, PeerKey, Session};
use enxame_metainfo::{InfoHash, Layout, Metainfo};
use enxame_peer::{Handshake, PeerMessage, decode_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

mod tracker;

/// Our fixed client peer-id prefix (Azureus style: `-EX0100-`).
const PEER_ID_PREFIX: &[u8; 8] = b"-EX0100-";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let torrent_path = args.next().context("usage: enxamed <file.torrent> [out-dir]")?;
    let out_dir = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));

    let bytes = tokio::fs::read(&torrent_path)
        .await
        .with_context(|| format!("reading {torrent_path}"))?;
    let metainfo = Metainfo::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("parse torrent: {e}"))?;
    let Layout::SingleFile { length } = metainfo.info.layout else {
        bail!("MVP supports single-file torrents only; multi-file mapping is a follow-up");
    };
    let announce = metainfo
        .announce
        .clone()
        .context("torrent has no http announce URL (DHT/magnet is a follow-up)")?;

    let peer_id = make_peer_id();
    eprintln!(
        "enxame: {} — {} pieces, {} bytes, info-hash {}",
        metainfo.info.name,
        metainfo.info.piece_count(),
        length,
        metainfo.info_hash
    );

    // 1. Announce to the tracker → a set of peer addresses.
    let peers = tracker::announce(&announce, metainfo.info_hash, peer_id, 6881, length)
        .await
        .context("tracker announce")?;
    eprintln!("enxame: tracker returned {} peers", peers.len());

    // 2. The engine + the I/O wiring.
    let mut session = Session::new(metainfo.info.clone());
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(1024);
    // Per-peer outbound channels (engine → peer task).
    let mut outbound: HashMap<PeerKey, mpsc::Sender<PeerMessage>> = HashMap::new();

    let info_hash = metainfo.info_hash;
    for (i, addr) in peers.into_iter().enumerate() {
        let key = i as PeerKey;
        let (out_tx, out_rx) = mpsc::channel::<PeerMessage>(256);
        outbound.insert(key, out_tx);
        let ev = event_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = peer_task(key, addr, info_hash, peer_id, ev.clone(), out_rx).await {
                let _ = ev.send(Event::PeerGone(key)).await;
                eprintln!("enxame: peer {key} ({addr}) ended: {e}");
            }
        });
    }
    drop(event_tx); // the spawned clones keep it alive

    // 3. The driver loop: events → engine → actions → I/O.
    let out_path = out_dir.join(&metainfo.info.name);
    let file = Arc::new(tokio::sync::Mutex::new(
        prepare_output(&out_path, length).await.context("preparing output file")?,
    ));
    let piece_length = metainfo.info.piece_length;

    while let Some(event) = event_rx.recv().await {
        // The block bytes need to survive into the disk write, so capture
        // before the engine consumes the event.
        let pending_write = match &event {
            Event::Message(_, PeerMessage::Piece { index, begin, data }) => {
                Some((*index, *begin, data.clone()))
            }
            _ => None,
        };
        for action in session.on_event(event) {
            match action {
                Action::Send(key, msg) => {
                    if let Some(tx) = outbound.get(&key) {
                        let _ = tx.send(msg).await;
                    }
                }
                Action::PieceVerified(index) => {
                    eprintln!(
                        "enxame: piece {index} verified ({}/{})",
                        session.have_count(),
                        session.piece_count()
                    );
                }
                Action::PieceCorrupt(index) => {
                    eprintln!("enxame: piece {index} FAILED verification — re-picking");
                }
                Action::Disconnect(key) => {
                    outbound.remove(&key);
                }
                Action::Complete => {
                    eprintln!("enxame: download complete → {}", out_path.display());
                    return Ok(());
                }
            }
        }
        // Persist the block (the engine verifies; we lay bytes down).
        if let Some((index, begin, data)) = pending_write {
            let offset = u64::from(index) * piece_length + u64::from(begin);
            write_at(&file, offset, &data).await.context("writing block to disk")?;
        }
    }

    eprintln!(
        "enxame: peers exhausted — {}/{} pieces. (DHT/PEX would find more.)",
        session.have_count(),
        session.piece_count()
    );
    Ok(())
}

/// Build a 20-byte peer id: the `-EX0100-` prefix + a 12-byte tail
/// derived from the process id (deterministic, dependency-free; a real
/// random tail is a trivial follow-up).
fn make_peer_id() -> [u8; 20] {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(PEER_ID_PREFIX);
    let pid = std::process::id().to_le_bytes();
    for (i, slot) in id[8..].iter_mut().enumerate() {
        *slot = b'0' + (pid[i % pid.len()] % 10);
    }
    id
}

/// Connect to one peer, handshake, and pump the wire both ways.
async fn peer_task(
    key: PeerKey,
    addr: SocketAddr,
    info_hash: InfoHash,
    peer_id: [u8; 20],
    events: mpsc::Sender<Event>,
    mut outbound: mpsc::Receiver<PeerMessage>,
) -> Result<()> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .context("connect timeout")??;

    // Handshake.
    stream.write_all(&Handshake::new(info_hash.0, peer_id).encode()).await?;
    let mut hs = [0u8; Handshake::LEN];
    stream.read_exact(&mut hs).await?;
    let remote = Handshake::parse(&hs).map_err(|e| anyhow::anyhow!("bad handshake: {e}"))?;
    if remote.info_hash != info_hash.0 {
        bail!("peer offered a different info-hash");
    }
    events.send(Event::PeerReady(key)).await.ok();

    let (mut rd, mut wr) = stream.into_split();
    // Writer task: drain the engine's outbound messages to the socket.
    let writer = tokio::spawn(async move {
        while let Some(msg) = outbound.recv().await {
            if wr.write_all(&msg.encode()).await.is_err() {
                break;
            }
        }
    });

    // Reader: accumulate bytes, decode complete frames, forward as events.
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = rd.read(&mut chunk).await?;
        if n == 0 {
            break; // peer closed
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some((msg, consumed)) =
            decode_frame(&buf).map_err(|e| anyhow::anyhow!("frame: {e}"))?
        {
            buf.drain(..consumed);
            if events.send(Event::Message(key, msg)).await.is_err() {
                writer.abort();
                return Ok(());
            }
        }
    }
    writer.abort();
    Ok(())
}

/// Create (or open) the output file and size it to `length`.
async fn prepare_output(path: &std::path::Path, length: u64) -> Result<tokio::fs::File> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .await?;
    file.set_len(length).await?;
    Ok(file)
}

async fn write_at(
    file: &Arc<tokio::sync::Mutex<tokio::fs::File>>,
    offset: u64,
    data: &[u8],
) -> Result<()> {
    use tokio::io::AsyncSeekExt;
    let mut f = file.lock().await;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    f.write_all(data).await?;
    Ok(())
}
