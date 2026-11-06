//! Stalled-link deselect end-to-end test.
//!
//! Validates the stall-latch lifecycle over a real bond: a black-holed link
//! is pulled from rotation (latch engages), the stream survives on the
//! healthy link, and once the link heals the latch releases only after the
//! rejoin dwell. The release assertion also exercises the duplicate-probe
//! path end-to-end: on a near-zero-RTT veth pair the keepalive-RTT probe is
//! armed only every ~3 s, which is sparser than the staleness window, so the
//! probes' earned SRTLA ACKs are what keep the recovery run's delivery proof
//! continuously fresh enough to complete the dwell.

mod common;

use std::time::Duration;

use network_sim::{ImpairmentConfig, SrtlaTestStack};

/// Lowered staleness ceiling. The latch must engage and the blackhole must
/// end well inside CONN_TIMEOUT (5 s): a timed-out link resets its latch, and
/// the whole point here is observing the latch survive to a warm rejoin.
const STALE_CEILING_MS: &str = "1500";

#[test]
fn test_stall_gate_latches_and_rejoins_after_dwell() {
    if common::skip_without_impairment_deps() {
        return;
    }
    common::build_srtla_send();

    // Lowered in-flight floor too: at 400 pkt/s over two near-zero-RTT veths a
    // link's backlog peaks around 15 packets, below the default 32, so the
    // stall signal could never arm. NAK-driven window cuts also steer traffic
    // off the dead link within milliseconds, which caps the backlog further.
    let mut stack = SrtlaTestStack::start(
        "stall",
        2,
        &[
            "--stall-ack-stale-ms",
            STALE_CEILING_MS,
            "--stall-min-in-flight",
            "8",
        ],
    )
    .expect("start stack");
    common::wait_until_ready(&stack);

    // Real SRT data, not the raw 0xB8 stream: in-flight accounting only counts
    // packets with an SRT data sequence number, and the stall signal needs it.
    stack.start_srt_caller().expect("start srt caller");

    // Continuous load throughout: selection (which drives the latch) runs per
    // routed packet, and the black-holed link must accumulate the >=32
    // in-flight backlog the stall signal requires.
    common::inject_srt_stream(&stack, 400, Duration::from_secs(2)).expect("warmup stream");

    // The stall latch is meant to act on Live links. On a near-zero-RTT veth
    // the keepalive-RTT probe arms only every ~3 s, so two probes outlast the
    // 5 s warming timeout and links can still be Warming here. Keep the load
    // up until both links have left Warming, then black-hole one.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while stack.sender_live_link_count() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "links never left the Warming phase"
        );
        common::inject_srt_stream(&stack, 400, Duration::from_millis(500)).expect("warming stream");
    }

    // Black-hole link 0 in BOTH directions, like a tunnel. A sender-egress-only
    // blackhole leaves the receiver's broadcast SRT ACKs arriving on the link,
    // and the silence pull (keyed on any inbound byte) correctly never fires.
    stack
        .impair_link_both_ways(
            0,
            ImpairmentConfig {
                loss_percent: Some(100.0),
                ..Default::default()
            },
        )
        .expect("blackhole link 0");

    // Latch expected after ~1.5 s of proof staleness; 3 s of load leaves
    // margin while keeping the blackhole shorter than CONN_TIMEOUT.
    common::inject_srt_stream(&stack, 400, Duration::from_secs(3))
        .expect("stream during blackhole");

    stack
        .impair_link_both_ways(0, ImpairmentConfig::default())
        .expect("restore link 0");

    // Rejoin dwell is 2x the effective staleness window (3 s here). Keep the
    // stream up so duplicate probes earn the gated link continuous ACK proof.
    common::inject_srt_stream(&stack, 400, Duration::from_secs(8))
        .expect("stream through recovery");

    let output = stack.stop();
    common::dump_output(&output);

    // tracing writes to stdout by default; search both streams for the log lines.
    let stderr: String = output
        .srtla_send_stdout
        .iter()
        .chain(output.srtla_send_stderr.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        stderr.contains("silence pull engaged"),
        "black-holed link never hit the fast silence pull"
    );
    assert!(
        stderr.contains("stall latch engaged"),
        "black-holed link never engaged the stall latch"
    );
    assert!(
        stderr.contains("stall latch released after sustained proof"),
        "healed link never completed the rejoin dwell (is duplicate probing delivering proof?)"
    );
    assert!(
        !stderr.contains("PANIC") && !stderr.contains("panic"),
        "srtla_send panicked during the stall-gate lifecycle"
    );
}
