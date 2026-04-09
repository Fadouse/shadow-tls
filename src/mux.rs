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
use monoio::io::{AsyncReadRent, AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::TcpStream;

use crate::util::prelude::*;
use crate::util::{mod_tcp_conn, resolve, FrameAead, PaddingState};

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
const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Max buffered outbound bytes before backpressure.
const WRITE_CHANNEL_CAP: usize = 256;

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
    sessions: RefCell<Vec<Rc<MuxSession>>>,
    max_sessions: usize,
    /// Serializes session creation so concurrent connections don't each
    /// independently create their own TLS session (thundering herd).
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

    /// Get a session with available capacity, or None if a new one is needed.
    pub(crate) fn get_session(&self) -> Option<Rc<MuxSession>> {
        let sessions = self.sessions.borrow();
        sessions.iter().find(|s| s.has_capacity()).cloned()
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

    /// Register a new session.
    pub(crate) fn add_session(&self, session: Rc<MuxSession>) {
        self.sessions.borrow_mut().push(session);
    }

    /// Remove dead sessions and sessions idle longer than MUX_IDLE_TIMEOUT.
    pub(crate) fn cleanup(&self) {
        let now = Instant::now();
        self.sessions.borrow_mut().retain(|s| {
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
) {
    use std::ptr::copy_nonoverlapping;

    let mut buffer = Vec::with_capacity(32768);
    let mut padding = PaddingState::new();

    let result: () = async {
    loop {
        // Wait for at least one frame
        let first = match rx.recv().await {
            Some(f) => f,
            None => return, // Channel closed — session dead
        };

        // Build inner payload: serialize first frame + drain channel for more
        let mut inner = Vec::with_capacity(4096);
        first.encode(&mut inner);

        // Drain any immediately available frames (coalescing)
        while inner.len() < MAX_INNER_PAYLOAD - 64 {
            match rx.try_recv() {
                Ok(f) => f.encode(&mut inner),
                Err(_) => break,
            }
        }

        // Build the TLS record
        buffer.clear();
        buffer.resize(TLS_HEADER_SIZE, 0);
        buffer[0] = APPLICATION_DATA;
        buffer[1] = TLS_MAJOR;
        buffer[2] = TLS_MINOR.0;

        // [TAG:16] will be filled after encryption
        buffer.resize(TLS_HMAC_HEADER_SIZE, 0);

        // Append the inner payload (will be encrypted)
        buffer.extend_from_slice(&inner);

        // Add padding (clamped so TLS record payload stays ≤ 16384)
        let current_payload = HMAC_SIZE + inner.len();
        let mut pad_len = padding.next_padding_len(current_payload);
        let max_pad = MAX_INNER_PAYLOAD.saturating_sub(inner.len());
        pad_len = pad_len.min(max_pad);
        if pad_len > 0 {
            buffer.resize(buffer.len() + pad_len, 0);
            rand::Rng::fill(&mut rand::thread_rng(), &mut buffer[TLS_HMAC_HEADER_SIZE + inner.len()..]);
        }

        // Write TLS record length
        let frame_len = buffer.len() - TLS_HEADER_SIZE;
        (&mut buffer[3..5])
            .write_u16::<BigEndian>(frame_len as u16)
            .unwrap();

        // Encrypt
        let header: [u8; TLS_HEADER_SIZE] = buffer[..TLS_HEADER_SIZE].try_into().unwrap();
        let tag = aead.encrypt_and_advance(&header, &mut buffer[TLS_HMAC_HEADER_SIZE..]);
        unsafe {
            copy_nonoverlapping(
                tag.as_ptr(),
                buffer.as_mut_ptr().add(TLS_HEADER_SIZE),
                HMAC_SIZE,
            )
        };

        let (res, buf) = tls_write.write_all(buffer).await;
        buffer = buf;
        if res.is_err() {
            return;
        }
    }
    }.await;
    // Write loop exiting — mark session dead and unblock all streams
    let _ = result;
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
) {
    mux_read_loop_inner(tls_read, &session, &mut aead, auth_pending).await;
    // Read loop exiting — mark session dead and unblock all streams
    session.shutdown();
}

async fn mux_read_loop_inner(
    tls_read: impl monoio::io::AsyncReadRent,
    session: &MuxSession,
    aead: &mut FrameAead,
    auth_pending: bool,
) {
    use crate::util::BufferFrameDecoder;
    const INIT_BUFFER_SIZE: usize = 4096;
    /// Max bytes/time discarded during auth-pending phase.
    const AUTH_PENDING_MAX_BYTES: usize = 64 * 1024;
    const AUTH_PENDING_MAX_SECS: u64 = 10;

    let mut decoder = BufferFrameDecoder::new(tls_read, INIT_BUFFER_SIZE);
    let mut decrypt_buf: Vec<u8> = Vec::with_capacity(16384);
    let mut authenticated = !auth_pending;
    let mut pending_bytes_discarded: usize = 0;
    let auth_deadline = if auth_pending {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(AUTH_PENDING_MAX_SECS))
    } else {
        None
    };

    loop {
        let maybe_frame = match decoder.next().await {
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

        let header: [u8; TLS_HEADER_SIZE] = frame[..TLS_HEADER_SIZE].try_into().unwrap();
        let mut tag = [0u8; HMAC_SIZE];
        tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

        decrypt_buf.clear();
        decrypt_buf.extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);

        if !aead.decrypt_and_advance(&header, &mut decrypt_buf, &tag) {
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

        // Parse all mux frames from the decrypted payload (coalesced)
        let mut pos = 0;
        while pos < decrypt_buf.len() {
            match MuxFrame::decode(&decrypt_buf[pos..]) {
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

    let session = Rc::new(MuxSession {
        write_tx,
        streams: streams.clone(),
        next_stream_id: Cell::new(2), // server uses even IDs (reserved)
        active_count: Cell::new(0),
        idle_since: Cell::new(Some(Instant::now())),
        dead: Cell::new(false),
    });

    let (tls_read, tls_write) = tls.into_split();

    // Handle the first SYN
    if let MuxFrame::Syn { stream_id, .. } = first_syn {
        let data_addr = resolve(target_addr).await?;
        spawn_server_stream(
            session.clone(),
            stream_id,
            data_addr,
            nodelay,
        );
    }

    // Spawn the write loop
    let session_for_read = session.clone();
    let target_addr = target_addr.to_string();

    // Override the read loop to also handle SYN by spawning new data connections
    let nodelay_val = nodelay;
    let read_handle = monoio::spawn(async move {
        use crate::util::BufferFrameDecoder;
        const INIT_BUFFER_SIZE: usize = 4096;

        let mut decoder = BufferFrameDecoder::new(tls_read, INIT_BUFFER_SIZE);
        let mut aead = aead_decrypt;
        let mut decrypt_buf: Vec<u8> = Vec::with_capacity(16384);

        loop {
            let maybe_frame = match decoder.next().await {
                Ok(f) => f,
                Err(_) => return,
            };
            let frame = match maybe_frame {
                Some(f) => f,
                None => return,
            };

            if frame[0] != APPLICATION_DATA || frame.len() < TLS_HMAC_HEADER_SIZE {
                continue;
            }

            let header: [u8; TLS_HEADER_SIZE] = frame[..TLS_HEADER_SIZE].try_into().unwrap();
            let mut tag = [0u8; HMAC_SIZE];
            tag.copy_from_slice(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);

            decrypt_buf.clear();
            decrypt_buf.extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);

            if !aead.decrypt_and_advance(&header, &mut decrypt_buf, &tag) {
                tracing::warn!("mux server: AEAD verification failed");
                return;
            }

            let mut pos = 0;
            while pos < decrypt_buf.len() {
                match MuxFrame::decode(&decrypt_buf[pos..]) {
                    Some((mux_frame, consumed)) => {
                        pos += consumed;
                        match &mux_frame {
                            MuxFrame::Syn { stream_id, .. } => {
                                // New stream: connect to data server
                                if let Ok(addr) = resolve(&target_addr).await {
                                    spawn_server_stream(
                                        session_for_read.clone(),
                                        *stream_id,
                                        addr,
                                        nodelay_val,
                                    );
                                }
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
    });

    // Run the write loop in the current task
    mux_write_loop(tls_write, write_rx, aead_encrypt, session.clone()).await;

    Ok(())
}

/// Spawn a server-side stream relay: connects to the data server and
/// bridges it with the mux stream.
fn spawn_server_stream(
    session: Rc<MuxSession>,
    stream_id: u32,
    data_addr: std::net::SocketAddr,
    nodelay: bool,
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

        // Bidirectional relay: mux stream <-> data server
        let session_for_read = session_clone.clone();
        let sid = stream_id;
        let _ = monoio::join!(
            // Data server -> mux stream (read from data server, send via mux)
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
                            if !session_for_read.send_data(sid, buf[..n].to_vec()) {
                                return;
                            }
                        }
                    }
                }
            },
            // Mux stream -> data server (receive from mux, write to data server)
            async {
                let mut data_write = data_write;
                while let Some(data) = data_rx.recv().await {
                    let (res, _) = data_write.write_all(data).await;
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
) -> Rc<MuxSession> {
    let (write_tx, write_rx) = local_sync::mpsc::unbounded::channel();
    let streams = Rc::new(RefCell::new(HashMap::new()));

    let session = Rc::new(MuxSession {
        write_tx,
        streams: streams.clone(),
        next_stream_id: Cell::new(1), // client uses odd IDs
        active_count: Cell::new(0),
        idle_since: Cell::new(Some(Instant::now())),
        dead: Cell::new(false),
    });

    let (tls_read, tls_write) = tls.into_split();

    // Spawn write loop
    monoio::spawn(mux_write_loop(tls_write, write_rx, aead_encrypt, session.clone()));

    // Spawn read loop
    let session_for_read = session.clone();
    // Client side: auth_pending=true to drain handshake residue (NewSessionTickets etc.)
    monoio::spawn(mux_read_loop(tls_read, session_for_read, aead_decrypt, true));

    session
}
