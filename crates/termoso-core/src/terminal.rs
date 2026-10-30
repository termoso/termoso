//! Protocol-agnostic interactive terminal session.
//!
//! The UI (xterm.js) only needs three things from a terminal: a stream of
//! output bytes, a way to write input bytes and a way to report size changes.
//! SSH shells, local PTYs and Telnet all implement [`TerminalSession`] so the
//! desktop tab code does not care which one it is talking to.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::error::Result;

/// Terminal geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24 }
    }
}

/// Something the terminal produced.
#[derive(Debug, Clone)]
pub enum TermEvent {
    /// Bytes for the screen.
    Output(Bytes),
    /// The remote signalled a title change or similar out-of-band info the
    /// UI may show (currently only the SSH auth banner).
    Notice(String),
    /// The process/shell exited.
    Exit {
        /// Exit status if known.
        code: Option<u32>,
        /// Signal name if killed by one.
        signal: Option<String>,
    },
    /// Transport error; the session is dead.
    Error(String),
    /// Channel closed cleanly.
    Closed,
}

/// Receiving end of a terminal's event stream.
pub type TermEvents = mpsc::Receiver<TermEvent>;

/// Sending half handed to implementations.
pub type TermSink = mpsc::Sender<TermEvent>;

/// Buffer between the transport and the UI in events.
pub const EVENT_BUFFER: usize = 1024;

/// Upper bound on scrollback lines any Termoso terminal keeps, whatever the
/// settings say. A full 100 000 × 200-cell grid is roughly 200 MB in the
/// alacritty grid, which is where the limit stops being a feature.
pub const MAX_SCROLLBACK_LINES: u32 = 100_000;

/// Clamp a user-provided scrollback setting to [`MAX_SCROLLBACK_LINES`].
pub fn clamp_scrollback(lines: u32) -> u32 {
    lines.min(MAX_SCROLLBACK_LINES)
}

/// Create the event channel used by every implementation.
pub fn event_channel() -> (TermSink, TermEvents) {
    mpsc::channel(EVENT_BUFFER)
}

/// An open interactive session.
#[async_trait]
pub trait TerminalSession: Send + Sync {
    /// Send keyboard input.
    async fn write(&self, data: &[u8]) -> Result<()>;
    /// Tell the far side the window was resized.
    async fn resize(&self, size: TermSize) -> Result<()>;
    /// Close the session (best effort; idempotent).
    async fn close(&self) -> Result<()>;
    /// Human-readable kind (`ssh`, `local`, `telnet`, `serial`).
    fn kind(&self) -> &'static str;
}

/// Shared, type-erased session handle.
pub type SharedTerminal = Arc<dyn TerminalSession>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrollback_is_capped() {
        assert_eq!(clamp_scrollback(500), 500);
        assert_eq!(clamp_scrollback(MAX_SCROLLBACK_LINES), MAX_SCROLLBACK_LINES);
        assert_eq!(clamp_scrollback(u32::MAX), MAX_SCROLLBACK_LINES);
    }
}
