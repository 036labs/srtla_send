//! Blackout rescue: per-link copies of recently sent SRT data packets, resent
//! on the healthy links the moment the stall gate pulls a link.
//!
//! Without it, packets stranded on a link that just went dark (tunnel, lift,
//! handover) are only recovered end to end: the SRT receiver notices the gap,
//! NAKs, and the SRT sender retransmits. That costs at least one more round
//! trip on top of the stall detection, and it is the classic IRL glitch. The
//! sender already knows which packets are stranded — the gated link's packet
//! log — so it can resend them itself, immediately.
//!
//! Safe on the wire: the copy carries the original SRT sequence number with the
//! retransmit flag set, the same way duplicate probes do, so an SRT receiver
//! that already has the packet discards it and one that does not slots it in.
//!
//! This module is the pure half (the ring, the trigger, the counters). The
//! shell owns the I/O: it records each routed data packet here and drains a
//! pending rescue onto the healthy links (see `sender::packet_handler`).

use std::collections::VecDeque;

use smallvec::SmallVec;

use super::SrtlaConnection;
use crate::seq::{seq_after, seq_normalize};

/// Most packets a link keeps for rescue. At 10 Mbps on one link (~950 pkt/s)
/// this is about a second of traffic, which is longer than the silence-pull
/// window plus any sane round trip, so it covers everything that can be in
/// flight when the gate fires. Bounds memory at ~1.3 MB per link.
pub const RESCUE_RING_MAX_PACKETS: usize = 1024;

/// Age past which a kept packet is evicted on the next record, whatever the
/// count. Well past any SRT latency budget a rescue could still beat.
pub const RESCUE_RING_MAX_AGE_MS: u64 = 3_000;

/// Oldest packet worth rescuing when the SRT peer has not declared its receive
/// buffer yet. Past the receiver's latency budget a packet is dropped on
/// arrival anyway, so resending it only costs bandwidth.
pub const RESCUE_DEFAULT_MAX_AGE_MS: u64 = 1_000;

/// Most packets resent per rescue event. Keeps a stall on a heavily loaded link
/// from dumping an unbounded burst onto the survivors; the oldest packets go
/// first, being closest to their deadline.
pub const RESCUE_MAX_PACKETS_PER_EVENT: usize = 512;

#[derive(Debug)]
struct RescueEntry {
    seq: i32,
    sent_ms: u64,
    data: Vec<u8>,
}

/// A packet handed back by [`SrtlaConnection::take_rescue`] for resending.
pub type RescuePacket = (u32, Vec<u8>);

/// Per-link rescue state: the ring of recent data packets, the pending-rescue
/// trigger, and lifetime counters.
#[derive(Debug, Default)]
pub struct RescueRing {
    entries: VecDeque<RescueEntry>,
    pending: bool,
    events: u64,
    packets: u64,
    bytes: u64,
}

impl RescueRing {
    /// Keep a copy of a routed data packet. Evicts by count and age, reusing the
    /// evicted buffer so the steady state does not allocate.
    pub fn record(&mut self, seq: i32, data: &[u8], now_ms: u64) {
        let cutoff = now_ms.saturating_sub(RESCUE_RING_MAX_AGE_MS);
        while self.entries.front().is_some_and(|e| e.sent_ms < cutoff) {
            self.entries.pop_front();
        }
        let mut buf = if self.entries.len() >= RESCUE_RING_MAX_PACKETS {
            self.entries.pop_front().map(|e| e.data).unwrap_or_default()
        } else {
            Vec::new()
        };
        buf.clear();
        buf.extend_from_slice(data);
        self.entries.push_back(RescueEntry {
            seq: seq_normalize(seq),
            sent_ms: now_ms,
            data: buf,
        });
    }

    /// Drop everything the receiver has cumulatively acknowledged. The ring is
    /// in send order, so this pops from the front until it meets a sequence the
    /// ACK does not cover; a straggler further back (an SRT retransmit queued
    /// after newer data) is filtered out at rescue time instead.
    pub fn prune_acked(&mut self, last_acked: i32) {
        let last_acked = seq_normalize(last_acked);
        while self
            .entries
            .front()
            .is_some_and(|e| !seq_after(e.seq, last_acked))
        {
            self.entries.pop_front();
        }
    }

    /// Number of packets currently kept.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is kept.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.pending = false;
    }
}

impl SrtlaConnection {
    /// Keep a copy of a data packet routed to this link, for rescue should the
    /// link stall. The shell calls this only with blackout rescue enabled.
    #[inline]
    pub fn record_for_rescue(&mut self, seq: u32, data: &[u8], now_ms: u64) {
        self.rescue.record(seq as i32, data, now_ms);
    }

    /// Arm a rescue. Called on the stall gate's rising edges (silence pull and
    /// latch). A no-op while the ring is empty, which is always the case with
    /// blackout rescue disabled, so the flag never asks the shell for work it
    /// cannot do.
    pub(crate) fn request_rescue(&mut self) {
        if !self.rescue.is_empty() {
            self.rescue.pending = true;
        }
    }

    /// Whether a rescue is armed and waiting for the shell.
    #[inline(always)]
    pub fn rescue_pending(&self) -> bool {
        self.rescue.pending
    }

    /// Disarm the rescue and hand back this link's stranded packets, oldest
    /// first: those still outstanding in the packet log (not acknowledged, not
    /// NAKed) and younger than `max_age_ms`, at most
    /// [`RESCUE_MAX_PACKETS_PER_EVENT`] of them.
    ///
    /// Drains the whole ring: rescued packets move to the links that carry the
    /// copies (the shell records them there), and the rest are either already
    /// delivered or too old to help. Packets still sitting in this link's batch
    /// queue are not in the packet log yet, so the shell flushes the queue
    /// before calling this.
    pub fn take_rescue(&mut self, now_ms: u64, max_age_ms: u64) -> SmallVec<RescuePacket, 64> {
        self.rescue.pending = false;
        let cutoff = now_ms.saturating_sub(max_age_ms);
        let mut out: SmallVec<RescuePacket, 64> = SmallVec::new();
        let packet_log = &self.packet_log;
        for e in self.rescue.entries.drain(..) {
            if out.len() >= RESCUE_MAX_PACKETS_PER_EVENT {
                break;
            }
            if e.sent_ms >= cutoff && packet_log.contains_key(&e.seq) {
                out.push((e.seq as u32, e.data));
            }
        }
        // `drain(..)` dropped on break empties the rest as well.
        if !out.is_empty() {
            self.rescue.events += 1;
        }
        out
    }

    /// Count packets the shell actually resent for this link.
    pub fn note_rescued(&mut self, packets: u64, bytes: u64) {
        self.rescue.packets += packets;
        self.rescue.bytes += bytes;
    }

    /// Cumulative rescue events (rescues that found stranded packets).
    #[inline(always)]
    pub fn rescue_events(&self) -> u64 {
        self.rescue.events
    }

    /// Cumulative packets resent on other links on this link's behalf.
    #[inline(always)]
    pub fn rescued_packets(&self) -> u64 {
        self.rescue.packets
    }

    /// Cumulative bytes resent on other links on this link's behalf.
    #[inline(always)]
    pub fn rescued_bytes(&self) -> u64 {
        self.rescue.bytes
    }

    /// Packets currently kept for rescue.
    #[inline(always)]
    pub fn rescue_ring_len(&self) -> usize {
        self.rescue.len()
    }

    pub(crate) fn clear_rescue(&mut self) {
        self.rescue.clear();
    }

    pub(crate) fn prune_rescue(&mut self, last_acked: i32) {
        if !self.rescue.is_empty() {
            self.rescue.prune_acked(last_acked);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::create_test_connection;

    #[test]
    fn ring_evicts_by_count_and_reuses_buffers() {
        let mut ring = RescueRing::default();
        for i in 0..(RESCUE_RING_MAX_PACKETS as i32 + 10) {
            ring.record(i, &[1, 2, 3], 1_000);
        }
        assert_eq!(ring.len(), RESCUE_RING_MAX_PACKETS);
        assert_eq!(ring.entries.front().unwrap().seq, 10);
    }

    #[test]
    fn ring_evicts_by_age_but_keeps_the_newest() {
        let mut ring = RescueRing::default();
        ring.record(1, &[0], 1_000);
        ring.record(2, &[0], 1_000 + RESCUE_RING_MAX_AGE_MS + 1);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.entries.front().unwrap().seq, 2);
    }

    #[test]
    fn prune_drops_acked_prefix_across_the_wrap() {
        let mut ring = RescueRing::default();
        let top = crate::seq::SEQ_MASK;
        for s in [top - 1, top, 0, 1, 2] {
            ring.record(s, &[0], 1_000);
        }
        ring.prune_acked(0);
        let left: Vec<i32> = ring.entries.iter().map(|e| e.seq).collect();
        assert_eq!(left, vec![1, 2]);
    }

    #[tokio::test]
    async fn take_returns_only_outstanding_young_packets_in_send_order() {
        let mut c = create_test_connection().await;
        for seq in 10u32..15 {
            c.record_for_rescue(seq, &[seq as u8; 4], 5_000);
        }
        c.record_for_rescue(20, &[9; 4], 1_000); // too old
        // 10 and 12 were acknowledged (not in the packet log); 20 is outstanding but old.
        for seq in [11, 13, 14, 20] {
            c.register_packet(seq, 5_000);
        }
        c.request_rescue();
        assert!(c.rescue_pending());

        let got = c.take_rescue(5_500, 1_000);
        let seqs: Vec<u32> = got.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![11, 13, 14]);
        assert_eq!(got[0].1, vec![11u8; 4]);
        assert!(!c.rescue_pending());
        assert_eq!(c.rescue_events(), 1);
        assert_eq!(c.rescue_ring_len(), 0, "the ring is drained by a rescue");
    }

    #[tokio::test]
    async fn request_is_a_no_op_with_an_empty_ring() {
        let mut c = create_test_connection().await;
        c.request_rescue();
        assert!(!c.rescue_pending());
    }

    #[tokio::test]
    async fn take_is_capped_per_event() {
        let mut c = create_test_connection().await;
        for seq in 0..(RESCUE_MAX_PACKETS_PER_EVENT as u32 + 50) {
            c.record_for_rescue(seq, &[0], 5_000);
            c.register_packet(seq as i32, 5_000);
        }
        let got = c.take_rescue(5_000, 1_000);
        assert_eq!(got.len(), RESCUE_MAX_PACKETS_PER_EVENT);
        assert_eq!(got[0].0, 0, "oldest first");
    }

    #[tokio::test]
    async fn srt_ack_prunes_the_ring() {
        let mut c = create_test_connection().await;
        for seq in 100u32..110 {
            c.record_for_rescue(seq, &[0], 5_000);
            c.register_packet(seq as i32, 5_000);
        }
        c.handle_srt_ack(104, 5_100, true);
        assert_eq!(c.rescue_ring_len(), 5);
    }
}
