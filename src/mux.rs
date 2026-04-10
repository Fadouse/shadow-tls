//! Connection multiplexing for ShadowTLS.
//!
//! Allows multiple logical streams over a single TLS connection, amortizing
//! the 1.5 RTT handshake cost. Compatible with the existing AEAD frame format:
//! mux commands live inside the encrypted inner payload.
//!
//! ## Wire format (inside AEAD-encrypted ApplicationData)
//!
//! ```text
//! CMD_MUX_SYN    = 0x02  [4B stream_id] [2B initial_window_kb]
//! CMD_MUX_DATA   = 0x03  [4B stream_id] [2B data_len] [data]
//! CMD_MUX_FIN    = 0x04  [4B stream_id]
//! CMD_MUX_RST    = 0x05  [4B stream_id]
//! CMD_MUX_WINDOW = 0x06  [4B stream_id] [4B window_delta]
//! CMD_MUX_PING   = 0x07  [4B ping_id]
//! CMD_MUX_PONG   = 0x08  [4B ping_id]
//! ```
//!
//! Multiple frames can be packed into a single TLS record (coalescing).
//! The receiver parses sequentially until the payload is exhausted.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use byteorder::{BigEndian, WriteBytesExt};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::TcpStream;

use crate::util::prelude::*;
use crate::util::{mod_tcp_conn, resolve, send_preamble, FrameAead, PaddingState, TrafficRole};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default initial per-stream receive window (256 KiB).
const DEFAULT_STREAM_WINDOW: u32 = 256 * 1024;
/// Max data bytes per MuxFrame::Data to keep the TLS record within 16384 bytes.
/// MuxFrame::Data header = 1 (cmd) + 4 (stream_id) + 2 (data_len) = 7 bytes.
pub(crate) const MAX_MUX_DATA: usize = MAX_INNER_PAYLOAD - 7;
/// Max streams per mux session.
const DEFAULT_MAX_STREAMS: usize = 128;
/// Idle timeout for a mux session with no active streams.
/// With keepalive pings every 15s resetting the timer, this only triggers
/// when the ping loop itself has died (session shutdown, write channel closed).
const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Keepalive ping interval for idle mux sessions.
const MUX_PING_INTERVAL: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// BufPool — thread-local buffer pool to avoid per-chunk Vec allocation
// ---------------------------------------------------------------------------

/// Reusable buffer pool for the mux data path.
///
/// Pre-allocates `MAX_MUX_DATA`-capacity Vecs so `extend_from_slice` never
/// reallocs on the hot path. Buffers are returned after the consumer writes
/// them to TCP. Drop-path leaks (write failures, RST) are bounded by the
/// pool cap (64 entries, ~1 MB max retained memory).
pub(crate) struct BufPool {
    pool: RefCell<Vec<Vec<u8>>>,
}

impl BufPool {
    pub(crate) fn new() -> Self {
        Self { pool: RefCell::new(Vec::new()) }
    }

    /// Take a buffer from the pool (or allocate a new one), fill with `data`.
    pub(crate) fn take(&self, data: &[u8]) -> Vec<u8> {
        let mut v = self.pool.borrow_mut().pop()
            .unwrap_or_else(|| Vec::with_capacity(MAX_MUX_DATA));
        v.clear();
        v.extend_from_slice(data);
        v
    }

    /// Return a consumed buffer to the pool. Drops silently if pool is full.
    pub(crate) fn put(&self, buf: Vec<u8>) {
        let mut pool = self.pool.borrow_mut();
        if pool.len() < 128 {
            pool.push(buf);
        }
    }
}

// ---------------------------------------------------------------------------
// MuxFrame — parsed representation of a mux command
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) enum MuxFrame {
    Syn { stream_id: u32, initial_window_kb: u16 },
    Data { stream_id: u32, payload: Vec<u8> },
    Fin { stream_id: u32 },
    Rst { stream_id: u32 },
    Window { stream_id: u32, delta: u32 },
    Ping { ping_id: u32 },
    Pong { ping_id: u32 },
}

impl MuxFrame {
    /// Serialize this frame into the buffer (unencrypted inner payload format).
    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            MuxFrame::Syn { stream_id, initial_window_kb } => {
                buf.push(CMD_MUX_SYN);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf.extend_from_slice(&initial_window_kb.to_be_bytes());
            }
            MuxFrame::Data { stream_id, payload } => {
                buf.push(CMD_MUX_DATA);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                let len = payload.len().min(u16::MAX as usize) as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&payload[..len as usize]);
            }
            MuxFrame::Fin { stream_id } => {
                buf.push(CMD_MUX_FIN);
                buf.extend_from_slice(&stream_id.to_be_bytes());
            }
            MuxFrame::Rst { stream_id } => {
                buf.push(CMD_MUX_RST);
                buf.extend_from_slice(&stream_id.to_be_bytes());
            }
            MuxFrame::Window { stream_id, delta } => {
                buf.push(CMD_MUX_WINDOW);
                buf.extend_from_slice(&stream_id.to_be_bytes());
                buf.extend_from_slice(&delta.to_be_bytes());
            }
            MuxFrame::Ping { ping_id } => {
                buf.push(CMD_MUX_PING);
                buf.extend_from_slice(&ping_id.to_be_bytes());
            }
            MuxFrame::Pong { ping_id } => {
                buf.push(CMD_MUX_PONG);
                buf.extend_from_slice(&ping_id.to_be_bytes());
            }
        }
    }

    /// Like `decode`, but uses the BufPool for Data payload allocation,
    /// reusing previously returned buffers instead of allocating new Vecs.
    pub(crate) fn decode_pooled(data: &[u8], pool: &BufPool) -> Option<(MuxFrame, usize)> {
        if data.is_empty() {
            return None;
        }
        if data[0] == CMD_MUX_DATA {
            if data.len() < 7 { return None; }
            let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
            let dlen = u16::from_be_bytes(data[5..7].try_into().unwrap()) as usize;
            if data.len() < 7 + dlen { return None; }
            let payload = pool.take(&data[7..7 + dlen]);
            return Some((MuxFrame::Data { stream_id: sid, payload }, 7 + dlen));
        }
        // Non-Data frames: fall through to standard decode (no allocation)
        Self::decode(data)
    }

    /// Parse one mux frame from a slice. Returns (frame, bytes_consumed) or None.
    pub(crate) fn decode(data: &[u8]) -> Option<(MuxFrame, usize)> {
        if data.is_empty() {
            return None;
        }
        let cmd = data[0];
        match cmd {
            CMD_MUX_SYN => {
                if data.len() < 7 { return None; }
                let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                let win = u16::from_be_bytes(data[5..7].try_into().unwrap());
                Some((MuxFrame::Syn { stream_id: sid, initial_window_kb: win }, 7))
            }
            CMD_MUX_DATA => {
                if data.len() < 7 { return None; }
                let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                let dlen = u16::from_be_bytes(data[5..7].try_into().unwrap()) as usize;
                if data.len() < 7 + dlen { return None; }
                let payload = data[7..7 + dlen].to_vec();
                Some((MuxFrame::Data { stream_id: sid, payload }, 7 + dlen))
            }
            CMD_MUX_FIN => {
                if data.len() < 5 { return None; }
                let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                Some((MuxFrame::Fin { stream_id: sid }, 5))
            }
            CMD_MUX_RST => {
                if data.len() < 5 { return None; }
                let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                Some((MuxFrame::Rst { stream_id: sid }, 5))
            }
            CMD_MUX_WINDOW => {
                if data.len() < 9 { return None; }
                let sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                let delta = u32::from_be_bytes(data[5..9].try_into().unwrap());
                Some((MuxFrame::Window { stream_id: sid, delta }, 9))
            }
            CMD_MUX_PING => {
                if data.len() < 5 { return None; }
                let pid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                Some((MuxFrame::Ping { ping_id: pid }, 5))
            }
            CMD_MUX_PONG => {
                if data.len() < 5 { return None; }
                let pid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                Some((MuxFrame::Pong { ping_id: pid }, 5))
            }
            _ => None, // Unknown command or PADDING — stop parsing
        }
    }
}

// ---------------------------------------------------------------------------
// Stream state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum StreamState {
    Open,
    LocalClosed,  // We sent FIN
    RemoteClosed, // Peer sent FIN
    Closed,       // Both sides closed
}

struct StreamEntry {
    /// Channel to deliver inbound data to the stream consumer.
    data_tx: local_sync::mpsc::unbounded::Tx<Vec<u8>>,
    state: StreamState,
}

// ---------------------------------------------------------------------------
// MuxSession — manages one TLS connection with multiplexed streams
// ---------------------------------------------------------------------------

pub(crate) struct MuxSession {
    /// Channel to send outbound frames to the write loop.
    write_tx: local_sync::mpsc::unbounded::Tx<MuxFrame>,
    /// Stream registry.
    streams: Rc<RefCell<HashMap<u32, StreamEntry>>>,
    /// Next client-initiated stream ID (odd: 1, 3, 5, ...).
    next_stream_id: Cell<u32>,
    /// Number of active (non-closed) streams.
    active_count: Cell<usize>,
    /// When the session last became idle (no active streams).
    /// `None` means it currently has at least one active stream.
    idle_since: Cell<Option<Instant>>,
    /// Set to true when the session's read or write loop dies.
    dead: Cell<bool>,
}

impl MuxSession {
    /// Check if this session is still alive (read/write loops running).
    pub(crate) fn is_alive(&self) -> bool {
        !self.dead.get()
    }

    /// Check if this session can accept more streams.
    pub(crate) fn has_capacity(&self) -> bool {
        self.is_alive() && self.active_count.get() < DEFAULT_MAX_STREAMS
    }

    /// Mark session as dead and close all stream data channels so that
    /// any blocked `data_rx.recv()` returns `None` immediately.
    pub(crate) fn shutdown(&self) {
        if self.dead.get() {
            return;
        }
        self.dead.set(true);
        // Drop all stream data_tx senders → unblocks data_rx.recv()
        let mut streams = self.streams.borrow_mut();
        streams.clear();
        self.active_count.set(0);
        tracing::debug!("mux session shut down, all streams closed");
    }

    /// Open a new client-initiated stream. Returns the stream ID and a
    /// receiver for inbound data.
    pub(crate) fn open_stream(
        &self,
    ) -> (u32, local_sync::mpsc::unbounded::Rx<Vec<u8>>) {
        let sid = self.next_stream_id.get();
        self.next_stream_id.set(sid + 2); // odd IDs for client

        let (data_tx, data_rx) = local_sync::mpsc::unbounded::channel();
        self.streams.borrow_mut().insert(sid, StreamEntry {
            data_tx,
            state: StreamState::Open,
        });
        if self.active_count.get() == 0 {
            self.idle_since.set(None);
        }
        self.active_count.set(self.active_count.get() + 1);

        // Send SYN to peer
        let _ = self.write_tx.send(MuxFrame::Syn {
            stream_id: sid,
            initial_window_kb: (DEFAULT_STREAM_WINDOW / 1024) as u16,
        });

        (sid, data_rx)
    }

    /// Send data on a stream.
    pub(crate) fn send_data(&self, stream_id: u32, data: Vec<u8>) -> bool {
        self.write_tx.send(MuxFrame::Data {
            stream_id,
            payload: data,
        }).is_ok()
    }

    /// Close (FIN) a stream from our side.
    pub(crate) fn close_stream(&self, stream_id: u32) {
        let _ = self.write_tx.send(MuxFrame::Fin { stream_id });
        let mut streams = self.streams.borrow_mut();
        if let Some(entry) = streams.get_mut(&stream_id) {
            match entry.state {
                StreamState::Open => entry.state = StreamState::LocalClosed,
                StreamState::RemoteClosed => {
                    entry.state = StreamState::Closed;
                    drop(streams);
                    self.remove_stream(stream_id);
                }
                _ => {}
            }
        }
    }

    fn remove_stream(&self, stream_id: u32) {
        self.streams.borrow_mut().remove(&stream_id);
        let count = self.active_count.get();
        if count > 0 {
            let new_count = count - 1;
            self.active_count.set(new_count);
            if new_count == 0 {
                self.idle_since.set(Some(Instant::now()));
            }
        }
    }

    /// Dispatch an inbound frame to the appropriate stream.
    fn dispatch_inbound(&self, frame: MuxFrame) {
        match frame {
            MuxFrame::Data { stream_id, payload } => {
                let streams = self.streams.borrow();
                if let Some(entry) = streams.get(&stream_id) {
                    let _ = entry.data_tx.send(payload);
                }
            }
            MuxFrame::Fin { stream_id } => {
                let mut streams = self.streams.borrow_mut();
                if let Some(entry) = streams.get_mut(&stream_id) {
                    match entry.state {
                        StreamState::Open => entry.state = StreamState::RemoteClosed,
                        StreamState::LocalClosed => {
                            entry.state = StreamState::Closed;
                            drop(streams);
                            self.remove_stream(stream_id);
                        }
                        _ => {}
                    }
                }
            }
            MuxFrame::Rst { stream_id } => {
                self.remove_stream(stream_id);
            }
            MuxFrame::Ping { ping_id } => {
                let _ = self.write_tx.send(MuxFrame::Pong { ping_id });
            }
            MuxFrame::Pong { .. } => {
                // Latency measurement — could be tracked, for now just acknowledge
            }
            MuxFrame::Syn { stream_id, .. } => {
                // Server-initiated streams — not used in current design
                tracing::debug!("ignoring server-initiated SYN for stream {stream_id}");
            }
            MuxFrame::Window { .. } => {
                // Flow control — future enhancement
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client-side: MuxPool manages reusable mux sessions
// ---------------------------------------------------------------------------

pub(crate) struct MuxPool {
    sessions: RefCell<Vec<(Rc<MuxSession>, Rc<BufPool>)>>,
    max_sessions: usize,
    creating: Cell<bool>,
}

impl MuxPool {
    pub(crate) fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RefCell::new(Vec::new()),
            max_sessions,
            creating: Cell::new(false),
        }
    }

    /// Get a session with available capacity and its associated buffer pool.
    pub(crate) fn get_session(&self) -> Option<(Rc<MuxSession>, Rc<BufPool>)> {
        let sessions = self.sessions.borrow();
        sessions.iter().find(|(s, _)| s.has_capacity()).cloned()
    }

    /// Try to acquire the creation lock. Returns true if this caller
    /// should create a session, false if another task is already creating.
    pub(crate) fn try_lock_create(&self) -> bool {
        if self.creating.get() {
            return false;
        }
        self.creating.set(true);
        true
    }

    pub(crate) fn unlock_create(&self) {
        self.creating.set(false);
    }

    /// Register a new session with its buffer pool. Evicts oldest idle if at capacity.
    pub(crate) fn add_session(&self, session: Rc<MuxSession>, pool: Rc<BufPool>) {
        let mut sessions = self.sessions.borrow_mut();
        if sessions.len() >= self.max_sessions {
            if let Some(idx) = sessions.iter().position(|(s, _)| !s.is_alive() || s.active_count.get() == 0) {
                sessions.swap_remove(idx);
            }
        }
        sessions.push((session, pool));
    }

    /// Remove dead sessions and sessions idle longer than MUX_IDLE_TIMEOUT.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        self.sessions.borrow_mut().retain(|(s, _)| {
            if !s.is_alive() {
                return false;
            }
            if s.active_count.get() == 0 {
                return s
                    .idle_since
                    .get()
                    .is_some_and(|t| now.duration_since(t) < MUX_IDLE_TIMEOUT);
            }
            true
        });
    }
}

// ---------------------------------------------------------------------------
// Mux write loop: serializes outbound frames into AEAD-encrypted TLS records
// ---------------------------------------------------------------------------

/// Runs the mux write loop: reads MuxFrames from the channel, packs them
/// into AEAD-encrypted TLS ApplicationData records, and writes to the TLS stream.
///
/// Coalesces multiple frames into one TLS record when they arrive in quick
/// succession (natural batching via channel drain).
pub(crate) async fn mux_write_loop(
    mut tls_write: impl monoio::io::AsyncWriteRent,
    mut rx: local_sync::mpsc::unbounded::Rx<MuxFrame>,
    mut aead: FrameAead,
    session: Rc<MuxSession>,
    pool: Rc<BufPool>,
    role: TrafficRole,
) {
    // Send preamble padding records mimicking HTTP/2 SETTINGS exchange.
    send_preamble(&mut tls_write, &mut aead, role).await;

    // Single buffer: [TLS_HDR:5][TAG:16][mux_frames...][padding...]
    // Frames are encoded directly here — no intermediate Vec allocation.
    let mut buffer = Vec::with_capacity(32768);
    let mut padding = PaddingState::new(role);

    // Encode a frame into buffer, then recycle any Data payload back to pool.
    #[inline]
    fn encode_and_recycle(frame: MuxFrame, buf: &mut Vec<u8>, pool: &BufPool) {
        frame.encode(buf);
        // After encode borrows &frame, destructure to reclaim owned payload
        if let MuxFrame::Data { payload, .. } = frame {
            pool.put(payload);
        }
    }

    let _: () = async {
    loop {
        let first = match rx.recv().await {
            Some(f) => f,
            None => return,
        };

        // Build TLS record header + tag placeholder
        buffer.clear();
        buffer.resize(TLS_HMAC_HEADER_SIZE, 0);
        buffer[0] = APPLICATION_DATA;
        buffer[1] = TLS_MAJOR;
        buffer[2] = TLS_MINOR.0;

        // Encode first frame + recycle its Data payload if any
        encode_and_recycle(first, &mut buffer, &pool);

        // Coalesce: drain channel for more frames (all recycled)
        while buffer.len() - TLS_HMAC_HEADER_SIZE < MAX_INNER_PAYLOAD - 64 {
            match rx.try_recv() {
                Ok(f) => encode_and_recycle(f, &mut buffer, &pool),
                Err(_) => break,
            }
        }

        let inner_len = buffer.len() - TLS_HMAC_HEADER_SIZE;

        // Padding (clamped to TLS record limit)
        let current_payload = HMAC_SIZE + inner_len;
        let mut pad_len = padding.next_padding_len(current_payload);
        pad_len = pad_len.min(MAX_INNER_PAYLOAD.saturating_sub(inner_len));
        if pad_len > 0 {
            // Padding is inside the AEAD envelope — ciphertext is
            // indistinguishable from random regardless of plaintext.
            buffer.resize(buffer.len() + pad_len, 0);
        }

        // TLS record length
        let frame_len = buffer.len() - TLS_HEADER_SIZE;
        (&mut buffer[3..5])
            .write_u16::<BigEndian>(frame_len as u16)
            .unwrap();

        // Encrypt in-place, write tag
        let header: [u8; TLS_HEADER_SIZE] = buffer[..TLS_HEADER_SIZE].try_into().unwrap();
        let tag = aead.encrypt_and_advance(&header, &mut buffer[TLS_HMAC_HEADER_SIZE..]);
        buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE].copy_from_slice(&tag);

        let (res, buf) = tls_write.write_all(buffer).await;
        buffer = buf;
        if res.is_err() {
            return;
        }
    }
    }.await;
    session.shutdown();
}

// ---------------------------------------------------------------------------
// Mux read loop: decrypts TLS records and dispatches to streams
// ---------------------------------------------------------------------------

/// Runs the mux read loop: reads AEAD-encrypted TLS ApplicationData records,
/// decrypts them, parses mux frames, and dispatches to the appropriate stream.
///
/// `auth_pending`: if true, discard frames that fail AEAD until the first valid
/// frame (drains verbatim handshake residue like NewSessionTickets). Once
/// authenticated, any AEAD failure is fatal. On the server side this is false
/// because the handshake drain happens before mux dispatch.
pub(crate) async fn mux_read_loop(
    tls_read: impl monoio::io::AsyncReadRent,
    session: Rc<MuxSession>,
    mut aead: FrameAead,
    auth_pending: bool,
    pool: Rc<BufPool>,
) {
    mux_read_loop_inner(tls_read, &session, &mut aead, auth_pending, &pool).await;
    // Read loop exiting — mark session dead and unblock all streams
    session.shutdown();
}

async fn mux_read_loop_inner(
    tls_read: impl monoio::io::AsyncReadRent,
    session: &MuxSession,
    aead: &mut FrameAead,
    auth_pending: bool,
    pool: &BufPool,
) {
    use crate::util::BufferFrameDecoder;
    /// Decoder buffer sized for a full TLS record to avoid early reallocation.
    const INIT_BUFFER_SIZE: usize = TLS_HEADER_SIZE + 16384;
    /// Max bytes/time discarded during auth-pending phase.
    const AUTH_PENDING_MAX_BYTES: usize = 64 * 1024;
    const AUTH_PENDING_MAX_SECS: u64 = 10;

    let mut decoder = BufferFrameDecoder::new(tls_read, INIT_BUFFER_SIZE);
    let mut authenticated = !auth_pending;
    let mut pending_bytes_discarded: usize = 0;
    let auth_deadline = if auth_pending {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(AUTH_PENDING_MAX_SECS))
    } else {
        None
    };

    loop {
        let maybe_frame = match decoder.next_mut().await {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("mux read loop error: {e}");
                return;
            }
        };
        let frame = match maybe_frame {
            Some(f) => f,
            None => return, // EOF
        };

        // Check auth-pending deadline
        if !authenticated {
            if let Some(dl) = auth_deadline {
                if std::time::Instant::now() >= dl {
                    tracing::warn!("mux auth pending: time limit exceeded");
                    return;
                }
            }
        }

        if frame[0] != APPLICATION_DATA || frame.len() < TLS_HMAC_HEADER_SIZE {
            if !authenticated {
                // AuthPending: discard non-ApplicationData (CCS, alerts, etc.)
                pending_bytes_discarded += frame.len();
                if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                    tracing::warn!("mux auth pending: byte limit exceeded");
                    return;
                }
                continue;
            }
            continue;
        }

        // Copy header and tag into locals before in-place decrypt.
        let header: [u8; TLS_HEADER_SIZE] = frame[..TLS_HEADER_SIZE].try_into().unwrap();
        let mut tag = [0u8; HMAC_SIZE];
        tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

        // Decrypt directly in the decoder's buffer — eliminates per-frame
        // memcpy into a separate decrypt_buf (~16 KB/frame).
        if !aead.decrypt_and_advance(&header, &mut frame[TLS_HMAC_HEADER_SIZE..], &tag) {
            if !authenticated {
                // AuthPending: discard non-AEAD frames (NewSessionTickets etc.)
                pending_bytes_discarded += frame.len();
                if pending_bytes_discarded > AUTH_PENDING_MAX_BYTES {
                    tracing::warn!("mux auth pending: byte limit exceeded");
                    return;
                }
                tracing::debug!("mux auth pending: discarding non-AEAD frame");
                continue;
            }
            tracing::warn!("mux: AEAD verification failed");
            return;
        }

        if !authenticated {
            tracing::debug!("mux auth pending → authenticated");
            authenticated = true;
        }

        // Parse all mux frames from in-place decrypted payload (coalesced).
        // Uses BufPool for Data payloads to reuse allocations.
        let plaintext = &frame[TLS_HMAC_HEADER_SIZE..];
        let mut pos = 0;
        while pos < plaintext.len() {
            match MuxFrame::decode_pooled(&plaintext[pos..], pool) {
                Some((mux_frame, consumed)) => {
                    pos += consumed;
                    session.dispatch_inbound(mux_frame);
                }
                None => break, // Remaining bytes are padding
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server-side: mux dispatch — handle incoming mux streams
// ---------------------------------------------------------------------------

/// Server-side mux dispatcher. Called when the first decrypted frame is
/// CMD_MUX_SYN instead of CMD_DATA. Manages the mux session and spawns
/// per-stream relays to the data server.
pub(crate) async fn mux_server_dispatch(
    tls: TcpStream,
    aead_encrypt: FrameAead,
    aead_decrypt: FrameAead,
    target_addr: &str,
    nodelay: bool,
    first_syn: MuxFrame, // The SYN that triggered mux mode
) -> anyhow::Result<()> {
    let (write_tx, write_rx) = local_sync::mpsc::unbounded::channel();

    let streams: Rc<RefCell<HashMap<u32, StreamEntry>>> = Rc::new(RefCell::new(HashMap::new()));
    let pool = Rc::new(BufPool::new());

    let session = Rc::new(MuxSession {
        write_tx,
        streams: streams.clone(),
        next_stream_id: Cell::new(2), // server uses even IDs (reserved)
        active_count: Cell::new(0),
        idle_since: Cell::new(Some(Instant::now())),
        dead: Cell::new(false),
    });

    let (tls_read, tls_write) = tls.into_split();

    // Pre-resolve data server address once (avoids per-stream DNS lookup).
    let data_addr = resolve(target_addr).await?;

    // Handle the first SYN
    if let MuxFrame::Syn { stream_id, .. } = first_syn {
        spawn_server_stream(
            session.clone(),
            stream_id,
            data_addr,
            nodelay,
            pool.clone(),
        );
    }

    // Spawn the write loop
    let session_for_read = session.clone();
    let nodelay_val = nodelay;
    let pool_for_read = pool.clone();
    let _read_handle = monoio::spawn(async move {
        use crate::util::BufferFrameDecoder;
        /// Decoder buffer sized for a full TLS record.
        const INIT_BUFFER_SIZE: usize = TLS_HEADER_SIZE + 16384;

        let mut decoder = BufferFrameDecoder::new(tls_read, INIT_BUFFER_SIZE);
        let mut aead = aead_decrypt;

        loop {
            let maybe_frame = match decoder.next_mut().await {
                Ok(f) => f,
                Err(_) => break,
            };
            let frame = match maybe_frame {
                Some(f) => f,
                None => break,
            };

            if frame[0] != APPLICATION_DATA || frame.len() < TLS_HMAC_HEADER_SIZE {
                continue;
            }

            let header: [u8; TLS_HEADER_SIZE] = frame[..TLS_HEADER_SIZE].try_into().unwrap();
            let mut tag = [0u8; HMAC_SIZE];
            tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

            // Decrypt in-place in the decoder's buffer.
            if !aead.decrypt_and_advance(&header, &mut frame[TLS_HMAC_HEADER_SIZE..], &tag) {
                tracing::warn!("mux server: AEAD verification failed");
                break;
            }

            // Parse mux frames from in-place decrypted payload using pool.
            let plaintext = &frame[TLS_HMAC_HEADER_SIZE..];
            let mut pos = 0;
            while pos < plaintext.len() {
                match MuxFrame::decode_pooled(&plaintext[pos..], &pool_for_read) {
                    Some((mux_frame, consumed)) => {
                        pos += consumed;
                        match &mux_frame {
                            MuxFrame::Syn { stream_id, .. } => {
                                spawn_server_stream(
                                    session_for_read.clone(),
                                    *stream_id,
                                    data_addr,
                                    nodelay_val,
                                    pool_for_read.clone(),
                                );
                            }
                            _ => {
                                session_for_read.dispatch_inbound(mux_frame);
                            }
                        }
                    }
                    None => break,
                }
            }
        }
        // Read loop exiting — shutdown session to unblock all waiting streams.
        // Without this, streams hang forever on data_rx.recv() when TLS drops.
        session_for_read.shutdown();
    });

    // Run the write loop in the current task
    mux_write_loop(tls_write, write_rx, aead_encrypt, session.clone(), pool, TrafficRole::Server).await;

    Ok(())
}

/// Spawn a server-side stream relay: connects to the data server and
/// bridges it with the mux stream.
fn spawn_server_stream(
    session: Rc<MuxSession>,
    stream_id: u32,
    data_addr: std::net::SocketAddr,
    nodelay: bool,
    pool: Rc<BufPool>,
) {
    let (data_tx, mut data_rx) = local_sync::mpsc::unbounded::channel::<Vec<u8>>();

    // Register the stream
    session.streams.borrow_mut().insert(stream_id, StreamEntry {
        data_tx,
        state: StreamState::Open,
    });
    session.active_count.set(session.active_count.get() + 1);

    let session_clone = session.clone();
    monoio::spawn(async move {
        // Connect to data server
        let mut data_stream = match TcpStream::connect_addr(data_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("mux stream {stream_id}: data server connect failed: {e}");
                session_clone.close_stream(stream_id);
                return;
            }
        };
        mod_tcp_conn(&mut data_stream, true, nodelay);

        let (data_read, data_write) = data_stream.into_split();

        let session_for_read = session_clone.clone();
        let pool_for_write = pool.clone();
        let sid = stream_id;
        let _ = monoio::join!(
            // Data server -> mux stream
            async {
                let mut data_read = data_read;
                let mut buf = vec![0u8; MAX_MUX_DATA];
                loop {
                    let (res, b) = data_read.read(buf).await;
                    buf = b;
                    match res {
                        Ok(0) | Err(_) => {
                            session_for_read.close_stream(sid);
                            return;
                        }
                        Ok(n) => {
                            if !session_for_read.send_data(sid, pool.take(&buf[..n])) {
                                return;
                            }
                        }
                    }
                }
            },
            // Mux stream -> data server (recycle buffers after write)
            async {
                let mut data_write = data_write;
                while let Some(data) = data_rx.recv().await {
                    let (res, written_buf) = data_write.write_all(data).await;
                    pool_for_write.put(written_buf);
                    if res.is_err() {
                        return;
                    }
                }
                let _ = data_write.shutdown().await;
            }
        );
    });
}

// ---------------------------------------------------------------------------
// Public: create a new client-side mux session over an existing TLS connection
// ---------------------------------------------------------------------------

/// Create a new MuxSession from an established TLS connection.
/// Returns the session and spawns the read/write loops.
pub(crate) fn create_client_session(
    tls: TcpStream,
    aead_encrypt: FrameAead,
    aead_decrypt: FrameAead,
) -> (Rc<MuxSession>, Rc<BufPool>) {
    let (write_tx, write_rx) = local_sync::mpsc::unbounded::channel();
    let streams = Rc::new(RefCell::new(HashMap::new()));
    let pool = Rc::new(BufPool::new());

    let session = Rc::new(MuxSession {
        write_tx,
        streams: streams.clone(),
        next_stream_id: Cell::new(1), // client uses odd IDs
        active_count: Cell::new(0),
        idle_since: Cell::new(Some(Instant::now())),
        dead: Cell::new(false),
    });

    let (tls_read, tls_write) = tls.into_split();

    // Spawn write loop (with pool for Data payload recycling)
    monoio::spawn(mux_write_loop(tls_write, write_rx, aead_encrypt, session.clone(), pool.clone(), TrafficRole::Client));

    // Spawn read loop (shares BufPool with write side for buffer recycling)
    let session_for_read = session.clone();
    let pool_for_read = pool.clone();
    monoio::spawn(mux_read_loop(tls_read, session_for_read, aead_decrypt, true, pool_for_read));

    // Spawn keepalive ping loop
    let session_for_ping = session.clone();
    monoio::spawn(async move {
        let mut ping_id: u32 = 0;
        loop {
            monoio::time::sleep(MUX_PING_INTERVAL).await;
            if !session_for_ping.is_alive() {
                return;
            }
            ping_id = ping_id.wrapping_add(1);
            if session_for_ping.write_tx.send(MuxFrame::Ping { ping_id }).is_err() {
                return;
            }
            // Reset idle timer unconditionally. No TOCTOU: monoio single-threaded,
            // no await points between here and end of block.
            session_for_ping.idle_since.set(Some(Instant::now()));
        }
    });

    (session, pool)
}
