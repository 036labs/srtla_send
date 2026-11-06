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

/// Most packets queued per rescue event. Keeps a stall on a heavily loaded
/// link from queueing an unbounded resend onto the survivors; the oldest
/// packets go first, being closest to their deadline.
pub const RESCUE_MAX_PACKETS_PER_EVENT: usize = 512;

/// Ceiling on banked pacing credit, so a link whose outbox sat blocked (no
/// healthy target) does not release its whole backlog in one burst when a
/// target appears.
const RESCUE_MAX_CREDIT: u32 = 32;

#[derive(Debug)]
struct RescueEntry {
    seq: i32,
    sent_ms: u64,
    data: Vec<u8>,
}

/// A packet handed back by [`SrtlaConnection::pop_rescue`] for resending.
pub type RescuePacket = (u32, Vec<u8>);

/// Totals of the rescue currently draining, reported when its outbox empties.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RescueTally {
    pub queued: u64,
    pub sent: u64,
    pub bytes: u64,
    pub expired: u64,
}

/// Per-link rescue state: the ring of recent data packets, the pending-rescue
/// trigger, the outbox of stranded packets waiting to be resent, pacing
/// credit, and counters.
#[derive(Debug, Default)]
pub struct RescueRing {
    entries: VecDeque<RescueEntry>,
    outbox: VecDeque<RescueEntry>,
    pending: bool,
    credit: u32,
    tally: RescueTally,
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
        self.outbox.clear();
        self.pending = false;
        self.credit = 0;
        self.tally = RescueTally::default();
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
    pub fn request_rescue(&mut self) {
        if !self.rescue.is_empty() {
            self.rescue.pending = true;
        }
    }

    /// Whether a rescue is armed and waiting for the shell.
    #[inline(always)]
    pub fn rescue_pending(&self) -> bool {
        self.rescue.pending
    }

    /// Disarm the rescue and move this link's stranded packets into its outbox,
    /// oldest first: those still outstanding in the packet log (not
    /// acknowledged, not NAKed) and younger than `max_age_ms`, at most
    /// [`RESCUE_MAX_PACKETS_PER_EVENT`] in the outbox. Returns how many were
    /// queued.
    ///
    /// Drains the whole ring: queued packets move to the links that carry the
    /// copies (the shell records them there), and the rest are either already
    /// delivered or too old to help. Packets still sitting in this link's batch
    /// queue are not in the packet log yet, so the shell flushes the queue
    /// before calling this.
    pub fn queue_rescue(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        self.rescue.pending = false;
        let cutoff = now_ms.saturating_sub(max_age_ms);
        let room = RESCUE_MAX_PACKETS_PER_EVENT.saturating_sub(self.rescue.outbox.len());
        let packet_log = &self.packet_log;
        let mut queued = 0;
        for e in self.rescue.entries.drain(..) {
            if queued >= room {
                break;
            }
            if e.sent_ms >= cutoff && packet_log.contains_key(&e.seq) {
                self.rescue.outbox.push_back(e);
                queued += 1;
            }
        }
        if queued > 0 {
            self.rescue.events += 1;
            self.rescue.tally.queued += queued as u64;
        }
        queued
    }

    /// Packets waiting in this link's rescue outbox.
    #[inline(always)]
    pub fn rescue_outbox_len(&self) -> usize {
        self.rescue.outbox.len()
    }

    /// Pacing: grant `packets` more resends to this link's outbox (one routed
    /// data packet's worth of pace), banked up to a small ceiling.
    pub fn add_rescue_credit(&mut self, packets: u32) {
        self.rescue.credit = self
            .rescue
            .credit
            .saturating_add(packets)
            .min(RESCUE_MAX_CREDIT);
    }

    /// Pacing: spend one resend of credit, if any is banked.
    pub fn spend_rescue_credit(&mut self) -> bool {
        if self.rescue.credit == 0 {
            return false;
        }
        self.rescue.credit -= 1;
        true
    }

    /// Next stranded packet to resend, oldest first, skipping (and counting)
    /// any that aged past `max_age_ms` while they waited.
    pub fn pop_rescue(&mut self, now_ms: u64, max_age_ms: u64) -> Option<RescuePacket> {
        let cutoff = now_ms.saturating_sub(max_age_ms);
        while let Some(e) = self.rescue.outbox.pop_front() {
            if e.sent_ms >= cutoff {
                return Some((e.seq as u32, e.data));
            }
            self.rescue.tally.expired += 1;
        }
        None
    }

    /// Drop (and count) packets at the front of the outbox that aged past
    /// `max_age_ms`, without taking a live one.
    pub fn drop_expired_rescue(&mut self, now_ms: u64, max_age_ms: u64) {
        let cutoff = now_ms.saturating_sub(max_age_ms);
        while self
            .rescue
            .outbox
            .front()
            .is_some_and(|e| e.sent_ms < cutoff)
        {
            self.rescue.outbox.pop_front();
            self.rescue.tally.expired += 1;
        }
    }

    /// Hand back the tally of the rescue that just drained, once the outbox is
    /// empty, and start a fresh one. `None` while packets are still waiting or
    /// nothing was queued.
    pub fn finish_rescue(&mut self) -> Option<RescueTally> {
        if !self.rescue.outbox.is_empty() || self.rescue.tally.queued == 0 {
            return None;
        }
        self.rescue.credit = 0;
        Some(std::mem::take(&mut self.rescue.tally))
    }

    /// Count packets the shell actually resent for this link.
    pub fn note_rescued(&mut self, packets: u64, bytes: u64) {
        self.rescue.packets += packets;
        self.rescue.bytes += bytes;
        self.rescue.tally.sent += packets;
        self.rescue.tally.bytes += bytes;
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

    fn drain(c: &mut SrtlaConnection, now: u64, max_age: u64) -> Vec<RescuePacket> {
        std::iter::from_fn(|| c.pop_rescue(now, max_age)).collect()
    }

    #[tokio::test]
    async fn queue_keeps_only_outstanding_young_packets_in_send_order() {
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

        assert_eq!(c.queue_rescue(5_500, 1_000), 3);
        assert!(!c.rescue_pending());
        assert_eq!(c.rescue_events(), 1);
        assert_eq!(c.rescue_ring_len(), 0, "the ring is drained by a rescue");
        assert_eq!(c.rescue_outbox_len(), 3);

        let got = drain(&mut c, 5_500, 1_000);
        let seqs: Vec<u32> = got.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![11, 13, 14]);
        assert_eq!(got[0].1, vec![11u8; 4]);
    }

    #[tokio::test]
    async fn request_is_a_no_op_with_an_empty_ring() {
        let mut c = create_test_connection().await;
        c.request_rescue();
        assert!(!c.rescue_pending());
    }

    #[tokio::test]
    async fn queue_is_capped_per_event() {
        let mut c = create_test_connection().await;
        for seq in 0..(RESCUE_MAX_PACKETS_PER_EVENT as u32 + 50) {
            c.record_for_rescue(seq, &[0], 5_000);
            c.register_packet(seq as i32, 5_000);
        }
        assert_eq!(c.queue_rescue(5_000, 1_000), RESCUE_MAX_PACKETS_PER_EVENT);
        assert_eq!(drain(&mut c, 5_000, 1_000)[0].0, 0, "oldest first");
    }

    #[tokio::test]
    async fn packets_that_age_out_while_waiting_are_skipped_and_counted() {
        let mut c = create_test_connection().await;
        c.record_for_rescue(1, &[0], 1_000);
        c.record_for_rescue(2, &[0], 1_400);
        c.register_packet(1, 1_000);
        c.register_packet(2, 1_400);
        assert_eq!(c.queue_rescue(1_500, 1_000), 2);
        // Held up (no healthy target) until seq 1 is past the budget.
        let got = drain(&mut c, 2_200, 1_000);
        assert_eq!(got.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![2]);
        c.note_rescued(1, 1);
        let t = c.finish_rescue().expect("outbox drained");
        assert_eq!((t.queued, t.sent, t.expired), (2, 1, 1));
        assert!(c.finish_rescue().is_none(), "a tally is reported once");
    }

    #[tokio::test]
    async fn pacing_credit_is_spent_one_resend_at_a_time_and_capped() {
        let mut c = create_test_connection().await;
        assert!(!c.spend_rescue_credit());
        c.add_rescue_credit(2);
        assert!(c.spend_rescue_credit());
        assert!(c.spend_rescue_credit());
        assert!(!c.spend_rescue_credit());
        c.add_rescue_credit(u32::MAX);
        let banked = std::iter::from_fn(|| c.spend_rescue_credit().then_some(())).count();
        assert_eq!(banked, RESCUE_MAX_CREDIT as usize);
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
