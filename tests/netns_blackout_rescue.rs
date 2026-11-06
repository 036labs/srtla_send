//! Blackout-rescue A/B measurement over a real bond.
//!
//! Runs the same scripted outage once per arm (baseline without rescue,
//! rescue sent at once, rescue paced with `--blackout-rescue-pace`) and
//! reports what the SRT receiver experienced in each. Two
//! links with a realistic round trip each, a tight SRT latency, a steady
//! stream through a real SRT caller, and a train of two-way blackouts that
//! alternate between the links (a tunnel takes one modem at a time).
//!
//! The headline number is the receiver's `packetsDropped`: packets that never
//! arrived before their TSBPD deadline, i.e. visible glitches. SRT's own ARQ
//! (NAK, then retransmit) races that deadline in both arms; the rescue arm
//! adds the sender-side resend when a link is pulled. Duplicates at the
//! receiver (`packets - packetsUnique`) price the overhead.
//!
//! This is a measurement, not a pass/fail gate on the benefit: whether rescue
//! beats SRT's ARQ depends on the receiver's NAK timing, the RTT and the
//! latency budget, which is exactly what the numbers are for. It asserts only
//! that every arm ran and that the rescue fired in the rescue arms only.
//! The table goes to stderr (`--nocapture`), and a JSON summary to
//! `$BR_SUMMARY` (default `/tmp/blackout_rescue_summary.json`). Each arm's
//! SRT stats and sender log stay in `/tmp/brsc_{off,on,pac}_srt/`.
//!
//! Tunables (env): `BR_LATENCY_MS` (default 400), `BR_DELAY_MS` one-way delay
//! per link (40, so an 80 ms RTT), `BR_CYCLES` (4), `BR_BLACKOUT_MS` (1500),
//! `BR_RECOVER_MS` (6000), `BR_PPS` (400), `BR_PACE` for the paced arm (1),
//! `BR_ARMS` to pick arms (`baseline,rescue,paced`).

mod common;

use std::path::PathBuf;
use std::time::Duration;

use network_sim::{ImpairmentConfig, SrtOptions, SrtlaTestStack};
use serde_json::{Value, json};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn stat(v: &Option<Value>, section: &str, key: &str) -> i64 {
    v.as_ref()
        .and_then(|v| v.get(section)?.get(key)?.as_i64())
        .unwrap_or(-1)
}

struct Params {
    latency_ms: u32,
    delay_ms: u32,
    cycles: u64,
    blackout_ms: u64,
    recover_ms: u64,
    pps: u32,
    pace: u32,
}

/// One arm: stand up the stack, run the outage train, return the summary.
/// `arm` is `baseline`, `rescue` or `paced`.
fn run_arm(arm: &str, p: &Params) -> Value {
    let name = match arm {
        "baseline" => "brsc_off",
        "rescue" => "brsc_on",
        _ => "brsc_pac",
    };
    let stats_dir = PathBuf::from(format!("/tmp/{name}_srt"));

    // Same stall tuning as the stall-gate test: the in-flight floor is lowered
    // so the silence pull can arm at this packet rate. Identical in every arm.
    let pace = p.pace.to_string();
    let mut args = vec!["--stall-min-in-flight", "8"];
    if arm != "baseline" {
        args.push("--blackout-rescue");
    }
    if arm == "paced" {
        args.extend(["--blackout-rescue-pace", pace.as_str()]);
    }
    let mut stack = SrtlaTestStack::start_with_srt(
        name,
        2,
        &args,
        SrtOptions {
            latency_ms: p.latency_ms,
            stats_dir: Some(stats_dir.clone()),
        },
    )
    .expect("start stack");
    common::wait_until_ready(&stack);

    // Realistic path delay, both directions, on both links. No jitter: netem
    // jitter reorders, which would add spurious NAKs to both arms and blur
    // the comparison.
    let path = ImpairmentConfig {
        delay_ms: Some(p.delay_ms),
        ..Default::default()
    };
    for i in 0..2 {
        stack
            .impair_link_both_ways(i, path.clone())
            .expect("apply path delay");
    }

    stack.start_srt_caller().expect("start srt caller");
    common::inject_srt_stream(&stack, p.pps, Duration::from_secs(2)).expect("warmup stream");
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    while stack.sender_live_link_count() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "links never left the Warming phase"
        );
        common::inject_srt_stream(&stack, p.pps, Duration::from_millis(500))
            .expect("warming stream");
    }
    let before_rx = stack.receiver_srt_stats();
    let before_tx = stack.caller_srt_stats();

    // One steady stream across the whole outage train.
    let train_ms = p.cycles * (p.blackout_ms + p.recover_ms) + 1_000;
    let mut stream = network_sim::spawn_udp_stream(
        &stack.topo.sender_ns,
        "127.0.0.1",
        network_sim::SRT_CALLER_INGEST_PORT,
        p.pps,
        network_sim::SRT_PAYLOAD_BYTES,
        Duration::from_millis(train_ms),
    )
    .expect("spawn stream");

    std::thread::sleep(Duration::from_millis(500));
    let blackhole = ImpairmentConfig {
        loss_percent: Some(100.0),
        ..Default::default()
    };
    for c in 0..p.cycles {
        let idx = (c % 2) as usize;
        stack
            .impair_link_both_ways(idx, blackhole.clone())
            .expect("blackhole");
        std::thread::sleep(Duration::from_millis(p.blackout_ms));
        stack
            .impair_link_both_ways(idx, path.clone())
            .expect("restore");
        std::thread::sleep(Duration::from_millis(p.recover_ms));
    }
    // Let the stream finish and the last stats report land.
    while stream.is_alive() {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(1_000));
    let rx = stack.receiver_srt_stats();
    let tx = stack.caller_srt_stats();

    let output = stack.stop();
    let log: Vec<String> = output
        .srtla_send_stdout
        .iter()
        .chain(output.srtla_send_stderr.iter())
        .cloned()
        .collect();
    // Keep the sender's log beside the SRT stats, for digging into a run.
    let _ = std::fs::write(stats_dir.join("sender.log"), log.join("\n"));
    assert!(
        !log.iter().any(|l| l.contains("panic")),
        "srtla_send panicked in the {name} arm"
    );

    // "...: blackout rescue resent N/M stranded packets (B bytes) ..."
    let (mut events, mut resent) = (0u64, 0u64);
    for l in log.iter().filter(|l| l.contains("blackout rescue resent")) {
        events += 1;
        if let Some(n) = l
            .split("resent ")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.parse::<u64>().ok())
        {
            resent += n;
        }
    }
    let pulls = log
        .iter()
        .filter(|l| l.contains("silence pull engaged"))
        .count();

    let d = |after: &Option<Value>, before: &Option<Value>, s: &str, k: &str| {
        stat(after, s, k) - stat(before, s, k).max(0)
    };
    let rx_packets = d(&rx, &before_rx, "recv", "packets");
    let rx_unique = d(&rx, &before_rx, "recv", "packetsUnique");
    json!({
        "arm": arm,
        "silence_pulls": pulls,
        "rescue_events": events,
        "rescued_packets": resent,
        "rx_packets": rx_packets,
        "rx_unique": rx_unique,
        "rx_duplicates": rx_packets - rx_unique,
        "rx_lost": d(&rx, &before_rx, "recv", "packetsLost"),
        "rx_dropped": d(&rx, &before_rx, "recv", "packetsDropped"),
        "rx_belated": d(&rx, &before_rx, "recv", "packetsBelated"),
        "rx_retransmitted": d(&rx, &before_rx, "recv", "packetsRetransmitted"),
        "tx_sent": d(&tx, &before_tx, "send", "packets"),
        "tx_retransmitted": d(&tx, &before_tx, "send", "packetsRetransmitted"),
        "tx_dropped": d(&tx, &before_tx, "send", "packetsDropped"),
        "stats_ok": rx.is_some() && tx.is_some(),
    })
}

#[test]
fn test_blackout_rescue_ab() {
    if common::skip_without_impairment_deps() {
        return;
    }
    common::build_srtla_send();

    let p = Params {
        latency_ms: env_u64("BR_LATENCY_MS", 400) as u32,
        delay_ms: env_u64("BR_DELAY_MS", 40) as u32,
        cycles: env_u64("BR_CYCLES", 4),
        blackout_ms: env_u64("BR_BLACKOUT_MS", 1_500),
        recover_ms: env_u64("BR_RECOVER_MS", 6_000),
        pps: env_u64("BR_PPS", 400) as u32,
        pace: env_u64("BR_PACE", 1) as u32,
    };
    let arms: Vec<String> = std::env::var("BR_ARMS")
        .unwrap_or_else(|_| "baseline,rescue,paced".into())
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| ["baseline", "rescue", "paced"].contains(&a.as_str()))
        .collect();
    assert!(!arms.is_empty(), "BR_ARMS names no known arm");
    let results: Vec<(String, Value)> = arms.iter().map(|a| (a.clone(), run_arm(a, &p))).collect();

    let rows = [
        "silence_pulls",
        "rescue_events",
        "rescued_packets",
        "rx_unique",
        "rx_duplicates",
        "rx_lost",
        "rx_dropped",
        "rx_belated",
        "rx_retransmitted",
        "tx_sent",
        "tx_retransmitted",
        "tx_dropped",
    ];
    eprintln!(
        "
blackout rescue A/B: latency {} ms, one-way delay {} ms, {} x {} ms blackouts, {} pkt/s, pace {}",
        p.latency_ms, p.delay_ms, p.cycles, p.blackout_ms, p.pps, p.pace
    );
    let mut head = format!("{:<18}", "metric");
    for (a, _) in &results {
        head += &format!(" {a:>10}");
    }
    eprintln!("{head}");
    for r in rows {
        let mut line = format!("{r:<18}");
        for (_, v) in &results {
            line += &format!(" {:>10}", v[r]);
        }
        eprintln!("{line}");
    }

    let mut summary = json!({
        "params": {
            "latency_ms": p.latency_ms, "delay_ms": p.delay_ms, "cycles": p.cycles,
            "blackout_ms": p.blackout_ms, "recover_ms": p.recover_ms, "pps": p.pps,
            "pace": p.pace,
        },
        "receiver": std::fs::read_to_string("/etc/srtla_rec_impl").unwrap_or_default().trim(),
    });
    for (a, v) in &results {
        summary[a] = v.clone();
    }
    let out =
        std::env::var("BR_SUMMARY").unwrap_or_else(|_| "/tmp/blackout_rescue_summary.json".into());
    let _ = std::fs::write(&out, serde_json::to_string_pretty(&summary).unwrap());

    for (a, v) in &results {
        assert_eq!(v["stats_ok"], true, "{a} arm produced no SRT stats");
        assert!(
            v["rx_unique"].as_i64().unwrap_or(0) > 0,
            "{a} arm delivered nothing"
        );
        if a == "baseline" {
            assert_eq!(v["rescue_events"], 0, "rescue fired with the flag off");
        } else {
            assert!(
                v["rescue_events"].as_u64().unwrap_or(0) > 0,
                "rescue never fired in the {a} arm"
            );
        }
    }
}
