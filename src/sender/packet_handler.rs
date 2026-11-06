use std::net::SocketAddr;

use anyhow::Result;
use smallvec::SmallVec;
use srtla_core::connection::{SrtlaConnection, SrtlaIncoming};
use srtla_core::registration::SrtlaRegistrationManager;
use srtla_core::selection::select_connection_idx;
use srtla_core::seq::srt_ack_last_acked;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, info, trace, warn};

use super::client_dedup::ClientDedup;
use super::connections::recover_connection;
use super::sequence::SequenceTracker;
use super::uplink::{ConnIoMap, UplinkPacket};
use crate::config::{ConfigSnapshot, DynamicConfig};

/// Type alias for instant ACK forwarding: (client_addr, packet_data)
pub type InstantForwarder = UnboundedSender<(SocketAddr, SmallVec<u8, 64>)>;

/// Attribute a NAK to the uplink that sent the lost packet and shrink its window.
///
/// Prefers the O(1) sequence-tracker mapping (the link that actually sent `nak`);
/// once that link is found we never fall through, so a duplicate NAK for an
/// already-cleared sequence can't be re-counted against a different link. Only
/// when the tracker has no record do we fall back to the first link that still
/// recognizes the sequence in its own packet log. Returns the index of the link
/// that counted the NAK, or `None` if none did. Production ignores the return;
/// it exists so the attribution path is unit-testable directly instead of mirrored.
pub(crate) fn attribute_nak(
    connections: &mut [SrtlaConnection],
    seq_tracker: &SequenceTracker,
    nak: u32,
    current_time_ms: u64,
) -> Option<usize> {
    if let Some(conn_id) = seq_tracker.get(nak, current_time_ms)
        && let Some(pos) = connections.iter().position(|c| c.conn_id == conn_id)
    {
        return connections[pos]
            .handle_nak(nak as i32, current_time_ms)
            .then_some(pos);
    }

    for (i, conn) in connections.iter_mut().enumerate() {
        if conn.handle_nak(nak as i32, current_time_ms) {
            return Some(i);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub async fn process_connection_events(
    idx: usize,
    connections: &mut [SrtlaConnection],
    last_client_addr: Option<SocketAddr>,
    local_listener: &UdpSocket,
    seq_tracker: &SequenceTracker,
    classic: bool,
    incoming: SrtlaIncoming,
) -> Result<()> {
    if idx >= connections.len() {
        return Ok(());
    }

    if !incoming.read_any
        && incoming.ack_numbers.is_empty()
        && incoming.nak_numbers.is_empty()
        && incoming.srtla_ack_numbers.is_empty()
        && incoming.forward_to_client.is_empty()
    {
        return Ok(());
    }

    // One monotonic read drives every ACK/NAK handler in this receive batch.
    let current_time_ms = srtla_core::utils::now_ms();

    for ack in incoming.ack_numbers.iter() {
        let last_acked = srt_ack_last_acked(*ack);
        // Every link prunes on a cumulative ACK — the receiver has the data,
        // whichever link carried it — but only the link that carried the
        // unique copy may take an RTT sample from it. The tracker never
        // records duplicate probes, so a probing link resolves to `None` here
        // and keeps its estimator free of round trips earned by the link that
        // actually delivered.
        let owner = seq_tracker.get(last_acked as u32, current_time_ms);
        for c in connections.iter_mut() {
            let owns = owner == Some(c.conn_id);
            c.handle_srt_ack(last_acked, current_time_ms, owns);
        }
    }

    for srtla_ack in incoming.srtla_ack_numbers.iter() {
        // Match the arrival link's packet log FIRST. The receiver sends an
        // SRTLA ACK back on the link that delivered the packet, and with
        // duplicate probing the same sequence can sit in two links' logs (the
        // unique copy and a probe). A first-log-wins scan would let the healthy
        // link's ACK stamp delivery proof on the gated link — falsely warming
        // its rejoin dwell. The fallback scan is kept for ACKs whose owner
        // can't be resolved from the arrival link (e.g. after a reconnect
        // cleared its log), but it is bookkeeping only: an ACK that arrived on
        // another link proves that link, so the owner gets no delivery proof,
        // RTT sample or window growth from it (`handle_srtla_ack_foreign`).
        let found_on_arrival =
            connections[idx].handle_srtla_ack_specific(*srtla_ack as i32, classic, current_time_ms);
        if !found_on_arrival {
            for (i, c) in connections.iter_mut().enumerate() {
                if i == idx {
                    continue;
                }
                if c.handle_srtla_ack_foreign(*srtla_ack as i32) {
                    break;
                }
            }
        }
        for c in connections.iter_mut() {
            c.handle_srtla_ack_global();
        }
    }

    for nak in incoming.nak_numbers.iter() {
        attribute_nak(connections, seq_tracker, *nak, current_time_ms);
    }

    if let Some(client) = last_client_addr {
        for pkt in incoming.forward_to_client.iter() {
            let _ = local_listener.send_to(pkt, client).await;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_uplink_packet(
    packet: UplinkPacket,
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    reg: &mut SrtlaRegistrationManager,
    instant_tx: &InstantForwarder,
    client_dedup: &mut ClientDedup,
    last_client_addr: Option<SocketAddr>,
    local_listener: &UdpSocket,
    seq_tracker: &SequenceTracker,
    config_snap: &ConfigSnapshot,
    config: &DynamicConfig,
) {
    if packet.bytes.is_empty() {
        return;
    }
    if let Some(idx) = connections.iter().position(|c| c.conn_id == packet.conn_id) {
        match super::uplink_recv::process_uplink_packet(
            &mut connections[idx],
            idx,
            reg,
            local_listener,
            instant_tx,
            last_client_addr,
            client_dedup,
            &packet.bytes,
        )
        .await
        {
            Ok(mut incoming) => {
                // Flush the deferred immediate-REG1 effect on this link's socket.
                if let Some(pkt) = incoming.reg1_send.take()
                    && let Some(io) = conn_io.get(&connections[idx].conn_id)
                {
                    match io.socket.send(&pkt).await {
                        Ok(_) => connections[idx].note_sent(srtla_core::utils::now_ms()),
                        Err(e) => {
                            warn!(
                                "{}: failed to send immediate REG1: {e}",
                                connections[idx].label
                            )
                        }
                    }
                }
                // The SRT peer told us how deep its receive buffer is. That is
                // the deadline every link is judged against, so it belongs on
                // the shared config where the next `ConfigSnapshot` picks it up
                // — not on the link that happened to carry the handshake.
                if let Some(latency_ms) = incoming.negotiated_latency_ms
                    && config.set_negotiated_latency_ms(latency_ms as u32)
                {
                    info!("SRT delivery budget is now {latency_ms}ms (from the peer's handshake)");
                }
                if let Err(err) = process_connection_events(
                    idx,
                    connections,
                    last_client_addr,
                    local_listener,
                    seq_tracker,
                    config_snap.mode.is_classic(),
                    incoming,
                )
                .await
                {
                    warn!("failed to apply uplink {} packet: {err}", packet.conn_id);
                }
            }
            Err(err) => warn!(
                "failed to process packet for uplink {}: {}",
                packet.conn_id, err
            ),
        }
    }
}

/// Maximum number of packets to process per drain call.
/// This prevents CPU spikes from processing large accumulated queues in one burst.
/// At ~1000 packets/sec typical rate, 64 packets = ~64ms worth of traffic.
const MAX_DRAIN_PACKETS: usize = 64;

#[allow(clippy::too_many_arguments)]
pub async fn drain_packet_queue(
    packet_rx: &mut UnboundedReceiver<UplinkPacket>,
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    reg: &mut SrtlaRegistrationManager,
    instant_tx: &InstantForwarder,
    client_dedup: &mut ClientDedup,
    last_client_addr: Option<SocketAddr>,
    local_listener: &UdpSocket,
    seq_tracker: &SequenceTracker,
    config_snap: &ConfigSnapshot,
    config: &DynamicConfig,
) {
    // Process up to MAX_DRAIN_PACKETS to prevent CPU spikes from large queue bursts.
    // Remaining packets will be processed on the next event loop iteration.
    let mut processed = 0;
    while processed < MAX_DRAIN_PACKETS {
        match packet_rx.try_recv() {
            Ok(packet) => {
                handle_uplink_packet(
                    packet,
                    connections,
                    conn_io,
                    reg,
                    instant_tx,
                    client_dedup,
                    last_client_addr,
                    local_listener,
                    seq_tracker,
                    config_snap,
                    config,
                )
                .await;
                processed += 1;
            }
            Err(_) => break, // No more packets available
        }
    }
}

/// Selects a connection to use during the pre-registration phase.
///
/// Selection priority:
/// 1. Last selected connection (if still connected and not timed out)
/// 2. Any non-timed-out connection
/// 3. None (if all connections are timed out)
fn select_pre_registration_connection(
    connections: &[SrtlaConnection],
    last_selected_idx: Option<usize>,
    now_ms: u64,
) -> Option<usize> {
    // Try to reuse the last selected connection if it's still valid
    if let Some(idx) = last_selected_idx
        && let Some(conn) = connections.get(idx)
        && conn.connected
        && !conn.is_timed_out(now_ms)
    {
        return Some(idx);
    }

    // Otherwise, find any non-timed-out connection
    connections
        .iter()
        .enumerate()
        .find(|(_, c)| !c.is_timed_out(now_ms))
        .map(|(i, _)| i)
}

/// Handle incoming SRT packet
///
/// Uses a pre-cached `ConfigSnapshot` to avoid atomic loads per packet.
/// The caller should create a snapshot once per select iteration for optimal performance.
///
/// When a keyframe burst is detected (runs of consecutive max-MTU 1316-byte data
/// packets), the scheduler overrides normal selection and routes to the
/// highest-quality link. This ensures I-frame data — which is critical for
/// decoder recovery — travels over the most reliable path.
#[allow(clippy::too_many_arguments)]
pub async fn handle_srt_packet(
    res: Result<(usize, SocketAddr), std::io::Error>,
    recv_buf: &mut [u8],
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    last_selected_idx: &mut Option<usize>,
    seq_tracker: &mut SequenceTracker,
    last_client_addr: &mut Option<SocketAddr>,
    registration_complete: bool,
    config_snap: &ConfigSnapshot,
    critical_window: &srtla_core::priority::CriticalWindow,
) {
    match res {
        Ok((n, src)) => {
            if n == 0 {
                return;
            }
            // Capture timestamp once at packet entry - reduces syscalls from 3-5 to 1 per packet
            let packet_time_ms = srtla_core::utils::now_ms();

            let pkt = &recv_buf[..n];
            let seq = srtla_protocol::get_srt_sequence_number(pkt);
            if !registration_complete {
                let sel_idx = select_pre_registration_connection(
                    connections,
                    *last_selected_idx,
                    packet_time_ms,
                );
                if let Some(sel_idx) = sel_idx {
                    forward_via_connection(
                        sel_idx,
                        pkt,
                        seq,
                        connections,
                        conn_io,
                        last_selected_idx,
                        seq_tracker,
                        packet_time_ms,
                    )
                    .await;
                }
                *last_client_addr = Some(src);
                return;
            }

            // Normal scheduler selection
            let mut sel_idx =
                select_connection_idx(connections, *last_selected_idx, packet_time_ms, config_snap);

            // Best-path override for must-land traffic. Two triggers share it:
            //
            // - Keyframe priority: the critical time window is opened over the
            //   priority sidecar by the encoder front-end, which parses NAL
            //   units and knows exactly when a keyframe / parameter set is in
            //   flight (see srtla_core::priority). srtla_send sees only opaque
            //   SRT payloads, so it never guesses at keyframes itself.
            // - SRT retransmits (R bit in the data header): a retransmit fills
            //   an existing hole in the receiver buffer, so it must not ride a
            //   score-crushed link — recovery traffic that arrives late is the
            //   steady-state glitch a degraded leg keeps causing even after
            //   routing has mostly moved off it.
            //
            // Only data packets have seq != None (control packets have MSB set).
            //
            // The override is enhanced-only: classic mode never consults the
            // quality cache, which only enhanced selection refreshes (and which
            // a runtime switch to classic leaves stale). In enhanced mode
            // `select_best_quality_idx` still declines (None) when every
            // eligible link is equally good, so the override only fires when
            // one path is actually better; otherwise these packets are
            // scheduled like any other (window / in-flight, times the link
            // weight).
            if seq.is_some()
                && (critical_window.is_critical_now(packet_time_ms)
                    || srtla_protocol::is_srt_data_retransmit(pkt))
                && let Some(best_idx) = srtla_core::priority::select_best_path_override_idx(
                    connections,
                    packet_time_ms,
                    config_snap.mode,
                )
                && sel_idx != Some(best_idx)
            {
                trace!(
                    "critical override (window/retransmit): link {} -> {}",
                    sel_idx.map_or(-1, |i| i as i64),
                    best_idx as i64
                );
                sel_idx = Some(best_idx);
            }

            if let Some(sel_idx) = sel_idx {
                forward_via_connection(
                    sel_idx,
                    pkt,
                    seq,
                    connections,
                    conn_io,
                    last_selected_idx,
                    seq_tracker,
                    packet_time_ms,
                )
                .await;
                if config_snap.blackout_rescue
                    && let Some(s) = seq
                {
                    connections[sel_idx].record_for_rescue(s, pkt, packet_time_ms);
                }
                if let Some(probe_seq) = seq {
                    send_stall_probes(
                        sel_idx,
                        pkt,
                        probe_seq,
                        connections,
                        conn_io,
                        seq_tracker,
                        packet_time_ms,
                    )
                    .await;
                }
                if config_snap.blackout_rescue {
                    rescue_stalled_links(
                        connections,
                        conn_io,
                        seq_tracker,
                        config_snap,
                        packet_time_ms,
                    )
                    .await;
                }
            } else {
                warn!("no available connection to forward packet from {}", src);
            }
            *last_client_addr = Some(src);
        }
        Err(e) => warn!("error reading local SRT: {}", e),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn forward_via_connection(
    sel_idx: usize,
    pkt: &[u8],
    seq: Option<u32>,
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    last_selected_idx: &mut Option<usize>,
    seq_tracker: &mut SequenceTracker,
    packet_time_ms: u64,
) {
    if sel_idx >= connections.len() {
        return;
    }
    if *last_selected_idx != Some(sel_idx) {
        if let Some(prev_idx) = *last_selected_idx {
            if prev_idx < connections.len() {
                // Deliberately does not flush the previous link's batch. Each
                // connection owns its BatchSender and drains it with a single
                // `sendmmsg` on its own size threshold or 15ms timer, so
                // interleaved routing just fills several per-link batches
                // concurrently instead of one serially — no syscall is lost.
                //
                // Flushing here emitted a one-packet batch on every switch,
                // which made per-packet scheduling expensive and is what the
                // `MIN_SWITCH_INTERVAL_MS` cooldown existed to suppress. That
                // cooldown freezes the selector for ~15ms, and since
                // `get_score()` counts queued packets as in-flight precisely so
                // routing a packet immediately de-prioritises its link, freezing
                // it opens that feedback loop and lets in-flight run away on one
                // link.
                debug!(
                    "Connection switch: {} → {} (seq: {:?})",
                    connections[prev_idx].label, connections[sel_idx].label, seq
                );
            }
        } else {
            debug!(
                "Initial connection selected: {} (seq: {:?})",
                connections[sel_idx].label, seq
            );
        }
        *last_selected_idx = Some(sel_idx);
    }

    // Get conn_id before mutable borrow for seq_tracker
    let conn_id = connections[sel_idx].conn_id;

    // Queue the packet for batched sending
    let needs_flush = connections[sel_idx].queue_data_packet(pkt, seq, packet_time_ms);

    // O(1) insert into ring buffer - no allocation
    // Track immediately when queued (not when flushed) for accurate NAK attribution
    if let Some(s) = seq {
        seq_tracker.insert(s, conn_id, packet_time_ms);
    }

    // Flush if batch threshold reached
    if needs_flush && let Some(io) = conn_io.get(&connections[sel_idx].conn_id) {
        let conn = &mut connections[sel_idx];
        flush_connection(conn, &io.socket, seq_tracker, "batch flush").await;
    }
}

/// Duplicate-packet probing on links held out of the rotation (librist-style
/// warm restore).
///
/// A held-out link carries no unique payload, so its only delivery proof would
/// be the 1 s keepalive echo — which proves the path echoes 38-byte control
/// frames, not that it can deliver data-sized packets. Instead, one in
/// [`srtla_core::config_snapshot::STALL_PROBE_ONE_IN_N`] routed data packets is
/// *also* queued on each held-out link. The copy reuses the original SRT
/// sequence number: the SRT receiver dedups it, so a lost or late probe can
/// never stall the receiver buffer, while a delivered one earns the link an
/// SRTLA ACK on its own socket — both the sustained delivery proof the rejoin
/// dwell requires and (since the ACK carries a round trip) the RTT sample the
/// recovery decision reads.
///
/// Covers both reasons a link is held out: the stall gate, and the quality
/// exclusion for a link that is *late* rather than merely under-used. The
/// distinction matters — a late link must not be given unique payload at all,
/// because a sequence number committed to a path running a second behind is
/// precisely the hole the receiver's reorder buffer stalls on, so the trickle
/// that keeps it measurable has to be redundant.
///
/// Deliberately NOT inserted into `seq_tracker`: the tracker must keep mapping
/// the sequence to the link that carried the unique copy, so a NAK still
/// penalizes the link that actually lost stream data. The SRTLA ACK for the
/// probe attributes correctly because `process_connection_events` matches the
/// arrival link first, and the probe is recorded in that link's own
/// sweep-proof probe log (see `SrtlaConnection::queue_probe_packet`) rather
/// than the packet log a cumulative ACK would prune it from.
async fn send_stall_probes(
    sel_idx: usize,
    pkt: &[u8],
    probe_seq: u32,
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    seq_tracker: &mut SequenceTracker,
    packet_time_ms: u64,
) {
    for (i, conn) in connections.iter_mut().enumerate() {
        if i == sel_idx {
            continue;
        }
        if !(conn.is_stall_gated() || conn.is_quality_excluded()) || !conn.connected {
            continue;
        }
        if !conn.stall_probe_due() {
            continue;
        }
        trace!(
            "{}: sending duplicate probe (seq {})",
            conn.label, probe_seq
        );
        // Flag the copy as a retransmission. The receiver dedups it by sequence
        // either way, but an SRTLA-patched receiver feeds every *non*-retransmit
        // into its reorder-hold estimator — the inter-link transit spread that
        // delays its loss reports. A probe from a link running a second behind
        // would pin that hold near its ceiling and slow recovery of real losses
        // on the healthy links, to no purpose: the probed link carries no unique
        // payload, so no gap is ever filled by waiting for it. See
        // `set_srt_data_retransmit` for why flipping the bit is safe on traffic
        // this proxy never decrypts.
        let mut probe: SmallVec<u8, 1500> = SmallVec::from_slice_copy(pkt);
        srtla_protocol::set_srt_data_retransmit(&mut probe);
        let needs_flush = conn.queue_probe_packet(&probe, probe_seq, packet_time_ms);
        if needs_flush && let Some(io) = conn_io.get(&conn.conn_id) {
            flush_connection(conn, &io.socket, seq_tracker, "probe batch flush").await;
        }
    }
}

/// Blackout rescue: resend a just-pulled link's stranded packets on the healthy
/// links.
///
/// The stall gate arms a rescue on its rising edges (see
/// `SrtlaConnection::request_rescue`); this runs right after selection, which
/// is where the gate is evaluated. Arming moves the link's still-outstanding
/// packets into its rescue outbox; every packet event then drains outboxes
/// onto the healthy links, oldest first. With `blackout_rescue_pace` = 0 an
/// outbox drains at once; with N it releases at most N packets per routed
/// data packet, so a rescue adds at most N times the stream's own rate. A
/// packet that waits past the SRT latency budget is dropped from the outbox.
/// While no healthy link is free (the other links are gated too) the outbox
/// simply waits for one.
///
/// Each copy keeps its SRT sequence number and gets the retransmit flag, like
/// a duplicate probe: a receiver that already has it discards it, one that
/// does not slots it in, and the flag keeps it out of an SRTLA receiver's
/// reorder-hold estimator. The copy is registered in-flight on the link that
/// carries it and recorded in that link's ring, so a second blackout can
/// rescue it again.
///
/// NAK ownership deliberately stays with the pulled link. The receiver keeps
/// NAKing the sequences that link lost, and those NAKs arrive after the rescue;
/// handing ownership to the carrying link made every one of them count as a
/// loss there, cutting the window of the one link carrying the stream (seen
/// in the A/B harness as a NAK burst and fast-recovery mode on the healthy
/// link within a round trip of each rescue). Blamed on the pulled link they
/// only cut a window that is gated anyway.
///
/// Targets come from the normal selector, one packet at a time: it already
/// skips gated links and counts queued packets against a link's score, so a
/// rescue spreads over the survivors instead of landing on one.
async fn rescue_stalled_links(
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    seq_tracker: &mut SequenceTracker,
    config_snap: &ConfigSnapshot,
    now_ms: u64,
) {
    let max_age_ms = match config_snap.negotiated_latency_ms {
        0 => srtla_core::connection::RESCUE_DEFAULT_MAX_AGE_MS,
        ms => ms as u64,
    };
    let pace = config_snap.blackout_rescue_pace;
    for i in 0..connections.len() {
        if connections[i].rescue_pending() {
            // Packets still in this link's batch queue are not in its packet
            // log yet; flush them (into the hole) so they register and get
            // rescued too.
            if let Some(io) = conn_io.get(&connections[i].conn_id) {
                flush_connection(
                    &mut connections[i],
                    &io.socket,
                    seq_tracker,
                    "pre-rescue flush",
                )
                .await;
            }
            let queued = connections[i].queue_rescue(now_ms, max_age_ms);
            if queued > 0 {
                debug!(
                    "{}: blackout rescue queued {queued} stranded packets",
                    connections[i].label
                );
            }
        }
        if connections[i].rescue_outbox_len() == 0 {
            continue;
        }
        if pace > 0 {
            connections[i].add_rescue_credit(pace);
        }
        let (mut sent, mut bytes) = (0u64, 0u64);
        while connections[i].rescue_outbox_len() > 0 {
            let Some(t) = select_connection_idx(connections, None, now_ms, config_snap) else {
                break;
            };
            if t == i {
                // No other link can take it right now (or this one spoke and
                // is schedulable again). Wait; the packet expires if this
                // lasts past its deadline.
                break;
            }
            if pace > 0 && !connections[i].spend_rescue_credit() {
                break;
            }
            let Some((seq, data)) = connections[i].pop_rescue(now_ms, max_age_ms) else {
                break;
            };
            let mut copy: SmallVec<u8, 1500> = SmallVec::from_slice_copy(&data);
            srtla_protocol::set_srt_data_retransmit(&mut copy);
            let target = &mut connections[t];
            let needs_flush = target.queue_data_packet(&copy, Some(seq), now_ms);
            target.record_for_rescue(seq, &copy, now_ms);
            if needs_flush && let Some(io) = conn_io.get(&target.conn_id) {
                flush_connection(target, &io.socket, seq_tracker, "rescue batch flush").await;
            }
            sent += 1;
            bytes += copy.len() as u64;
        }
        if sent > 0 {
            connections[i].note_rescued(sent, bytes);
        }
        // An outbox blocked with no target still ages out, so a rescue that
        // never found a healthy link ends (and is reported) on its own.
        connections[i].drop_expired_rescue(now_ms, max_age_ms);
        if let Some(t) = connections[i].finish_rescue() {
            info!(
                "{}: blackout rescue resent {}/{} stranded packets ({} bytes, {} expired) on \
                 healthy links",
                connections[i].label, t.sent, t.queued, t.bytes, t.expired
            );
        }
    }
}

/// Drain a connection's batch queue and transmit it on the link's socket.
///
/// The pure `take_batch` half (queue drain + in-flight registration) lives on
/// `SrtlaConnection`; this is the I/O half. `last_sent` is stamped here rather
/// than in `take_batch` so it only ever records I/O the socket confirmed.
///
/// Errors are not handled here — every caller goes through [`flush_connection`],
/// which owns the recovery arm.
async fn send_connection_batch(
    conn: &mut SrtlaConnection,
    socket: &crate::net::BatchUdpSocket,
) -> Result<(), crate::net::BatchSendError> {
    let now = srtla_core::utils::now_ms();
    let batch = conn.take_batch(now);
    if batch.is_empty() {
        return Ok(());
    }
    let bufs: SmallVec<&[u8], 32> = batch.iter().map(|(data, _, _)| data.as_slice()).collect();
    crate::net::send_all_datagrams(socket, &bufs).await?;
    conn.note_sent(now);
    Ok(())
}

/// Flush one link's batch and, if the socket refuses it, put the link into
/// recovery.
///
/// The single place a batch flush may fail. `take_batch` registers the whole
/// drained batch as in-flight *before* the I/O is attempted, and only
/// `mark_for_recovery` clears those registrations again — so a flush path that
/// merely logs its error leaves phantom in-flight packets that quietly crush the
/// link's score for as long as it stays up. All three flush paths (threshold,
/// probe, and the periodic timer) funnel through here so none can forget.
///
/// The unconfirmed remainder of a partial send is dropped deliberately, not
/// re-queued: recovery resets the link to `Registering` with a cold window and
/// an empty queue, so bytes pushed back onto it would be aimed at a path that is
/// being torn down. SRT's own NAK/retransmit refills the hole over whichever
/// links are healthy, which is exactly what should carry it.
async fn flush_connection(
    conn: &mut SrtlaConnection,
    socket: &crate::net::BatchUdpSocket,
    seq_tracker: &mut SequenceTracker,
    what: &str,
) {
    if let Err(e) = send_connection_batch(conn, socket).await {
        warn!("{}: {what} failed, marking for recovery: {}", conn.label, e);
        recover_connection(conn, seq_tracker);
    }
}

/// Flush all connection batches (called on timer or when needed)
///
/// Optimized with early exit: first check if any connection has queued packets
/// before iterating. This avoids work on the 15ms timer when traffic is idle.
pub async fn flush_all_batches(
    connections: &mut [SrtlaConnection],
    conn_io: &ConnIoMap,
    seq_tracker: &mut SequenceTracker,
) {
    // One monotonic read drives the flush-window check for every connection.
    let now = srtla_core::utils::now_ms();

    // Quick scan to check if any connection has work to do
    // This is a fast read-only check that avoids the flush logic entirely when idle
    let has_work = connections
        .iter()
        .any(|c| c.has_queued_packets() || c.needs_batch_flush(now));

    if !has_work {
        return;
    }

    // Now do the actual flush for connections that need it
    for conn in connections.iter_mut() {
        if (conn.needs_batch_flush(now) || conn.has_queued_packets())
            && let Some(io) = conn_io.get(&conn.conn_id)
        {
            flush_connection(conn, &io.socket, seq_tracker, "periodic batch flush").await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;
    use crate::net::{BatchUdpSocket, SourceIpBinder};
    use crate::sender::uplink::ConnIo;
    use crate::test_helpers::create_test_connection;

    /// An uplink whose socket can never send: an IPv4 socket pinned to an IPv6
    /// peer, so `sendmmsg`/`sendto` fails immediately (EAFNOSUPPORT / EINVAL)
    /// rather than blocking or succeeding. That is the whole fake-socket seam
    /// this test needs — a real socket that reliably rejects the batch — so no
    /// mock socket layer has to exist for it.
    fn unsendable_conn_io() -> ConnIo {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        socket.set_nonblocking(true).unwrap();
        let remote = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);
        ConnIo {
            socket: Arc::new(BatchUdpSocket::new(socket, remote).unwrap()),
            binder: Arc::new(SourceIpBinder),
            remote,
        }
    }

    /// The periodic 15ms flush used to only `warn!` when the socket refused the
    /// batch, while `take_batch` had already registered every packet in it as
    /// in-flight. That left phantom in-flight packets crushing the link's score
    /// (`window / (in_flight + 1)`) for as long as the link stayed up. The timer
    /// path must take the same recovery arm as the send-loop paths.
    #[tokio::test]
    async fn periodic_flush_failure_recovers_the_link() {
        let mut connections = vec![create_test_connection().await];
        let conn_id = connections[0].conn_id;
        let mut conn_io = ConnIoMap::new();
        conn_io.insert(conn_id, unsendable_conn_io());

        let now = srtla_core::utils::now_ms();
        let mut seq_tracker = SequenceTracker::new();
        connections[0].queue_data_packet(&[0u8; 1316], Some(4242), now);
        seq_tracker.insert(4242, conn_id, now);
        assert!(connections[0].has_queued_packets());
        assert!(connections[0].connected);

        flush_all_batches(&mut connections, &conn_io, &mut seq_tracker).await;

        assert_eq!(
            connections[0].in_flight_packets, 0,
            "a failed flush must not leave the batch registered as in-flight"
        );
        assert!(
            !connections[0].connected,
            "a failed flush must put the link into recovery"
        );
        assert!(
            connections[0].last_sent.is_none(),
            "nothing reached the socket, so the link must not claim a send"
        );
        assert!(
            seq_tracker.get(4242, now).is_none(),
            "recovery must drop the sequence ownership of the recovered link"
        );
    }

    /// The success side of the same seam: a confirmed flush registers the batch
    /// as in-flight, stamps `last_sent`, and leaves the link alone.
    #[tokio::test]
    async fn successful_flush_registers_the_batch_and_stamps_last_sent() {
        let mut connections = vec![create_test_connection().await];
        let conn_id = connections[0].conn_id;
        let conn_io = crate::test_helpers::create_test_conn_io_map(&connections);

        let now = srtla_core::utils::now_ms();
        let mut seq_tracker = SequenceTracker::new();
        connections[0].queue_data_packet(&[0u8; 1316], Some(7), now);
        seq_tracker.insert(7, conn_id, now);

        flush_all_batches(&mut connections, &conn_io, &mut seq_tracker).await;

        assert_eq!(connections[0].in_flight_packets, 1);
        assert!(connections[0].connected);
        assert!(connections[0].last_sent.is_some());
        assert_eq!(seq_tracker.get(7, now), Some(conn_id));
    }

    // --- Blackout rescue ---

    /// A minimal SRT data packet: sequence number in the first word (MSB
    /// clear = data), payload filled with the sequence's low byte.
    fn srt_data(seq: u32) -> Vec<u8> {
        let mut p = vec![seq as u8; 1316];
        p[..4].copy_from_slice(&seq.to_be_bytes());
        p[4..8].copy_from_slice(&[0; 4]);
        p
    }

    fn rescue_config() -> ConfigSnapshot {
        ConfigSnapshot {
            blackout_rescue: true,
            ..ConfigSnapshot::default()
        }
    }

    /// Link 0 is loaded and goes silent; link 1 is healthy. The silence pull
    /// must arm a rescue, and the rescue must move every stranded packet onto
    /// link 1 as a retransmit-flagged copy, while NAK ownership stays with
    /// link 0.
    #[tokio::test]
    async fn silence_pull_rescues_stranded_packets_onto_the_healthy_link() {
        use srtla_core::config_snapshot::STALL_MIN_IN_FLIGHT_PACKETS;

        let mut connections = crate::test_helpers::create_test_connections(2).await;
        let conn_io = crate::test_helpers::create_test_conn_io_map(&connections);
        let mut seq_tracker = SequenceTracker::new();
        let config = rescue_config();
        let now = srtla_core::utils::now_ms();
        let n = STALL_MIN_IN_FLIGHT_PACKETS as u32 + 8;

        for seq in 1..=n {
            connections[0].record_for_rescue(seq, &srt_data(seq), now - 100);
            connections[0].register_packet(seq as i32, now - 100);
            seq_tracker.insert(seq, connections[0].conn_id, now - 100);
        }
        // Delivery proof fresh (so only the fast tier is in play), but nothing
        // heard for longer than the pull window.
        connections[0].last_ack_or_rtt_sample_ms = now;
        connections[0].last_received = Some(now - 300);
        connections[1].last_ack_or_rtt_sample_ms = now;

        let sel = select_connection_idx(&mut connections, None, now, &config);
        assert_eq!(sel, Some(1));
        assert!(
            connections[0].rescue_pending(),
            "the pull must arm a rescue"
        );

        rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, now).await;

        assert!(!connections[0].rescue_pending());
        assert_eq!(connections[0].rescue_events(), 1);
        assert_eq!(connections[0].rescued_packets(), n as u64);
        assert_eq!(connections[0].rescued_bytes(), n as u64 * 1316);
        assert_eq!(connections[0].rescue_ring_len(), 0);
        assert_eq!(
            connections[0].in_flight_packets, n as i32,
            "the pulled link's own accounting is left for the cumulative ACK"
        );
        let pulled_id = connections[0].conn_id;
        for seq in 1..=n {
            assert_eq!(
                seq_tracker.get(seq, now),
                Some(pulled_id),
                "NAKs for a rescued packet stay blamed on the link that lost it"
            );
        }

        // On the wire, link 1 now carries the copies as tracked payload.
        flush_all_batches(&mut connections, &conn_io, &mut seq_tracker).await;
        assert_eq!(connections[1].in_flight_packets, n as i32);
        assert_eq!(connections[1].rescue_ring_len(), n as usize);
        // Read link 1's ring back through a rescue of its own.
        connections[1].request_rescue();
        assert_eq!(connections[1].queue_rescue(now, 1_000), n as usize);
        let again: Vec<_> = std::iter::from_fn(|| connections[1].pop_rescue(now, 1_000)).collect();
        assert_eq!(again.len(), n as usize);
        for (seq, data) in &again {
            assert!(
                srtla_protocol::is_srt_data_retransmit(data),
                "a rescued copy must carry the retransmit flag"
            );
            assert_eq!(srtla_protocol::get_srt_sequence_number(data), Some(*seq));
        }
    }

    /// With every link stalled there is nowhere to rescue to: the gate's
    /// any-healthy guard keeps the link schedulable, and the rescue must not
    /// resend a link's packets onto itself.
    #[tokio::test]
    async fn rescue_never_resends_onto_the_pulled_link_itself() {
        use srtla_core::config_snapshot::STALL_MIN_IN_FLIGHT_PACKETS;

        let mut connections = crate::test_helpers::create_test_connections(1).await;
        let conn_io = crate::test_helpers::create_test_conn_io_map(&connections);
        let mut seq_tracker = SequenceTracker::new();
        let config = rescue_config();
        let now = srtla_core::utils::now_ms();
        for seq in 1..=(STALL_MIN_IN_FLIGHT_PACKETS as u32) {
            connections[0].record_for_rescue(seq, &srt_data(seq), now);
            connections[0].register_packet(seq as i32, now);
        }
        connections[0].last_ack_or_rtt_sample_ms = now;
        connections[0].last_received = Some(now - 300);

        let _ = select_connection_idx(&mut connections, None, now, &config);
        rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, now).await;

        assert_eq!(connections[0].rescued_packets(), 0);
        assert!(!connections[0].has_queued_packets());
    }

    /// Paced: each packet event releases at most `pace` stranded packets, the
    /// oldest first, until the outbox is empty.
    #[tokio::test]
    async fn paced_rescue_releases_pace_packets_per_event() {
        use srtla_core::config_snapshot::STALL_MIN_IN_FLIGHT_PACKETS;

        let mut connections = crate::test_helpers::create_test_connections(2).await;
        let conn_io = crate::test_helpers::create_test_conn_io_map(&connections);
        let mut seq_tracker = SequenceTracker::new();
        let config = ConfigSnapshot {
            blackout_rescue_pace: 3,
            ..rescue_config()
        };
        let now = srtla_core::utils::now_ms();
        let n = STALL_MIN_IN_FLIGHT_PACKETS as u32 + 8;
        for seq in 1..=n {
            connections[0].record_for_rescue(seq, &srt_data(seq), now - 100);
            connections[0].register_packet(seq as i32, now - 100);
        }
        connections[0].last_ack_or_rtt_sample_ms = now;
        connections[0].last_received = Some(now - 300);
        connections[1].last_ack_or_rtt_sample_ms = now;
        let _ = select_connection_idx(&mut connections, None, now, &config);

        rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, now).await;
        assert_eq!(connections[0].rescued_packets(), 3);
        assert_eq!(connections[0].rescue_outbox_len(), n as usize - 3);

        let mut events = 1;
        while connections[0].rescue_outbox_len() > 0 {
            rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, now).await;
            events += 1;
            assert!(events < 100);
        }
        assert_eq!(connections[0].rescued_packets(), n as u64);
        assert_eq!(events, (n as usize).div_ceil(3));
    }

    /// With nowhere to send, the outbox waits for a healthy link rather than
    /// dropping the rescue, and expires what passes its deadline meanwhile.
    #[tokio::test]
    async fn blocked_rescue_waits_then_expires() {
        use srtla_core::config_snapshot::STALL_MIN_IN_FLIGHT_PACKETS;

        let mut connections = crate::test_helpers::create_test_connections(1).await;
        let conn_io = crate::test_helpers::create_test_conn_io_map(&connections);
        let mut seq_tracker = SequenceTracker::new();
        let config = rescue_config();
        let now = srtla_core::utils::now_ms();
        let n = STALL_MIN_IN_FLIGHT_PACKETS as u32;
        for seq in 1..=n {
            connections[0].record_for_rescue(seq, &srt_data(seq), now);
            connections[0].register_packet(seq as i32, now);
        }
        connections[0].last_ack_or_rtt_sample_ms = now;
        connections[0].last_received = Some(now - 300);
        let _ = select_connection_idx(&mut connections, None, now, &config);

        rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, now).await;
        assert_eq!(
            connections[0].rescue_outbox_len(),
            n as usize,
            "kept while blocked"
        );

        let later = now + srtla_core::connection::RESCUE_DEFAULT_MAX_AGE_MS + 1;
        rescue_stalled_links(&mut connections, &conn_io, &mut seq_tracker, &config, later).await;
        assert_eq!(
            connections[0].rescue_outbox_len(),
            0,
            "expired past the budget"
        );
        assert_eq!(connections[0].rescued_packets(), 0);
    }

    /// Off by default: a packet event records nothing, so the gate has nothing
    /// to arm and behaviour is unchanged.
    #[tokio::test]
    async fn rescue_is_inert_when_the_flag_is_off() {
        assert!(!ConfigSnapshot::default().blackout_rescue);
        let mut c = create_test_connection().await;
        c.register_packet(1, 0);
        assert_eq!(c.rescue_ring_len(), 0);
        assert!(!c.rescue_pending());
    }
}
