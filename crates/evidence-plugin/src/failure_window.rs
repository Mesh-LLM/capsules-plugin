//! The per-peer cap on the failed-exchange records a provider seals.
//!
//! A provider that sealed every request it refused would let anyone grow its
//! log for free: a stream of unpaid requests that each get a 402. So a failure
//! on a node that was to serve the request is sealed only for an identified
//! mesh peer (`ObservedLifecycleEvents::failed_asker`), and only up to
//! [`MAX_SEALED_PER_PEER`] per peer per [`WINDOW_SECS`]. Past the cap nothing
//! more is sealed for that peer in that window, and when the window closes the
//! provider seals ONE summary record for the peer with the count it did not
//! seal, so the gap is on the record. The requester side is not subject to
//! this: it chose to send each request, so it seals every failure of its own.
//!
//! Windows are fixed and aligned to the Unix epoch, so every node cuts them at
//! the same instants. A window closes lazily: the next failure from the same
//! peer in a later window, or the plugin's background tick (`due_summaries`),
//! whichever comes first, hands back its summary. Counts are in memory only: a
//! restart forgets the open window's, which can seal at most one more window's
//! worth of failures for a peer and loses that window's summary.

use std::collections::HashMap;
use std::sync::Mutex;

/// Failures sealed one by one for one peer in one window.
pub const MAX_SEALED_PER_PEER: u32 = 20;
/// The window the cap is counted over, in seconds.
pub const WINDOW_SECS: u32 = 3600;

/// What to do with one failure from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Seal it.
    Seal,
    /// Over the cap: count it for the summary and seal nothing.
    Over,
}

/// The failures not sealed for one peer in one closed window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub peer: String,
    /// Unix seconds, the window's aligned start.
    pub window_start: i64,
    pub window_s: u32,
    pub unsealed: u32,
}

struct PeerWindow {
    window: i64,
    sealed: u32,
    unsealed: u32,
}

pub struct FailureWindow {
    cap: u32,
    window_s: u32,
    peers: Mutex<HashMap<String, PeerWindow>>,
}

impl Default for FailureWindow {
    fn default() -> Self {
        Self::new(MAX_SEALED_PER_PEER, WINDOW_SECS)
    }
}

impl FailureWindow {
    pub fn new(cap: u32, window_s: u32) -> Self {
        assert!(window_s > 0, "a window has a length");
        Self {
            cap,
            window_s,
            peers: Mutex::new(HashMap::new()),
        }
    }

    fn window_of(&self, now: i64) -> i64 {
        now.div_euclid(i64::from(self.window_s))
    }

    fn summary(&self, peer: &str, entry: &PeerWindow) -> Option<Summary> {
        (entry.unsealed > 0).then(|| Summary {
            peer: peer.to_string(),
            window_start: entry.window * i64::from(self.window_s),
            window_s: self.window_s,
            unsealed: entry.unsealed,
        })
    }

    /// Count one failure from `peer` at `now` (Unix seconds). Returns what to
    /// do with it and, when this is the peer's first failure in a new window,
    /// the summary of the window that just closed for it.
    pub fn admit(&self, peer: &str, now: i64) -> (Admit, Option<Summary>) {
        let window = self.window_of(now);
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = peers.entry(peer.to_string()).or_insert(PeerWindow {
            window,
            sealed: 0,
            unsealed: 0,
        });
        let closed = if entry.window < window {
            let closed = self.summary(peer, entry);
            *entry = PeerWindow {
                window,
                sealed: 0,
                unsealed: 0,
            };
            closed
        } else {
            None
        };
        if entry.sealed < self.cap {
            entry.sealed += 1;
            (Admit::Seal, closed)
        } else {
            entry.unsealed += 1;
            (Admit::Over, closed)
        }
    }

    /// Close every window that ended before `now`: the summaries of those
    /// with failures left unsealed. The plugin's tick calls this, so a peer
    /// that stops sending still gets its summary.
    pub fn due_summaries(&self, now: i64) -> Vec<Summary> {
        let window = self.window_of(now);
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut due = Vec::new();
        peers.retain(|peer, entry| {
            if entry.window >= window {
                return true;
            }
            due.extend(self.summary(peer, entry));
            false
        });
        due.sort_by(|a, b| a.peer.cmp(&b.peer));
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 7 * 3600;

    #[test]
    fn seals_up_to_the_cap_then_counts() {
        let window = FailureWindow::new(2, 3600);
        assert_eq!(window.admit("a", T0).0, Admit::Seal);
        assert_eq!(window.admit("a", T0 + 1).0, Admit::Seal);
        assert_eq!(window.admit("a", T0 + 2).0, Admit::Over);
        assert_eq!(window.admit("a", T0 + 3).0, Admit::Over);
    }

    #[test]
    fn the_cap_is_per_peer() {
        let window = FailureWindow::new(1, 3600);
        assert_eq!(window.admit("a", T0).0, Admit::Seal);
        assert_eq!(window.admit("a", T0).0, Admit::Over);
        assert_eq!(window.admit("b", T0).0, Admit::Seal);
    }

    #[test]
    fn a_later_failure_closes_the_window_with_one_summary() {
        let window = FailureWindow::new(1, 3600);
        window.admit("a", T0);
        window.admit("a", T0 + 10);
        window.admit("a", T0 + 20);
        let (admit, closed) = window.admit("a", T0 + 3600);
        assert_eq!(admit, Admit::Seal, "a new window starts at zero");
        assert_eq!(
            closed,
            Some(Summary {
                peer: "a".into(),
                window_start: T0,
                window_s: 3600,
                unsealed: 2,
            })
        );
        assert_eq!(window.admit("a", T0 + 3601).1, None, "once per window");
    }

    #[test]
    fn a_window_with_nothing_over_the_cap_has_no_summary() {
        let window = FailureWindow::new(3, 3600);
        window.admit("a", T0);
        assert_eq!(window.admit("a", T0 + 3600).1, None);
        assert!(window.due_summaries(T0 + 7200).is_empty());
    }

    #[test]
    fn the_tick_closes_a_window_for_a_peer_that_went_quiet() {
        let window = FailureWindow::new(1, 3600);
        window.admit("a", T0);
        window.admit("a", T0 + 1);
        window.admit("b", T0);
        window.admit("b", T0 + 1);
        window.admit("b", T0 + 2);
        assert!(window.due_summaries(T0 + 3599).is_empty(), "still open");
        let due = window.due_summaries(T0 + 3600);
        assert_eq!(
            due.iter()
                .map(|s| (s.peer.as_str(), s.unsealed))
                .collect::<Vec<_>>(),
            [("a", 1), ("b", 2)]
        );
        assert!(
            window.due_summaries(T0 + 3600).is_empty(),
            "handed back once"
        );
        assert_eq!(window.admit("a", T0 + 3601).0, Admit::Seal);
    }

    #[test]
    fn windows_are_aligned_to_the_epoch() {
        let window = FailureWindow::new(1, 3600);
        window.admit("a", 3599);
        window.admit("a", 3599);
        let (_, closed) = window.admit("a", 3600);
        assert_eq!(closed.expect("closed").window_start, 0);
    }
}
