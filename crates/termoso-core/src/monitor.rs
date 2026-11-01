//! Live resource monitor for an SSH session: host name, CPU, memory, network
//! throughput, uptime, logged-in users and disk usage of the remote machine.
//!
//! Like [`crate::osdetect`] and [`crate::autocomplete`] it never touches the
//! interactive shell: [`PROBE_SCRIPT`] is piped to `sh` on a separate `exec`
//! channel, so nothing lands in the user's history or on their screen. The
//! script only reads `/proc` and runs `hostname`, `who` and `df`; hosts
//! without `/proc` (BSD, macOS, network gear) answer "unsupported".
//!
//! One probe returns *counters*; CPU load and network throughput are rates,
//! so [`Snapshot::from_samples`] needs the previous probe of the same session.

use std::time::Duration;

use serde::Serialize;

/// How long a single probe may take before it is abandoned.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

/// Most disks reported per probe.
pub const MAX_DISKS: usize = 6;

/// Most user names reported per probe.
pub const MAX_USERS: usize = 8;

/// POSIX `sh` script, fed on stdin. Output is `key=value` lines.
pub const PROBE_SCRIPT: &str = r#"LC_ALL=C
export LC_ALL
[ -r /proc/stat ] && [ -r /proc/meminfo ] || { echo unsupported=1; exit 0; }
printf 'host=%s\n' "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
awk '/^cpu /{print "cpu="$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9}' /proc/stat
awk '{print "uptime="$1}' /proc/uptime 2>/dev/null
awk '{print "load="$1" "$2" "$3}' /proc/loadavg 2>/dev/null
awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2; h=1} /^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} END{if(!h)a=f+b+c; print "mem="t" "a}' /proc/meminfo
awk -F'[: ]+' 'NR>2 && $2!="lo"{rx+=$3; tx+=$11} END{print "net="rx+0" "tx+0}' /proc/net/dev 2>/dev/null
who 2>/dev/null | awk '{print "user="$1}'
df -P -k 2>/dev/null | awk 'NR>1 && $1 ~ /^\//{m=$6; for(i=7;i<=NF;i++) m=m" "$i; print "disk="$2" "$3" "m}'
"#;

/// Monotonic counters from one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Jiffies spent doing work (everything but idle and iowait).
    pub cpu_busy: u64,
    /// All jiffies.
    pub cpu_total: u64,
    /// Bytes received on all non-loopback interfaces.
    pub rx_bytes: u64,
    /// Bytes sent on all non-loopback interfaces.
    pub tx_bytes: u64,
}

/// One mounted filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    /// Mount point.
    pub mount: String,
    /// Size in KiB.
    pub total_kb: u64,
    /// Used space in KiB.
    pub used_kb: u64,
}

/// What one probe returned.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Host name as the machine reports it.
    pub host: String,
    /// Seconds since boot.
    pub uptime_secs: u64,
    /// 1, 5 and 15 minute load average.
    pub load: Option<[f32; 3]>,
    /// Physical memory in KiB.
    pub mem_total_kb: u64,
    /// Memory available to new programs in KiB.
    pub mem_available_kb: u64,
    /// Distinct users with a login session (`who`).
    pub users: Vec<String>,
    /// Real (device-backed) filesystems.
    pub disks: Vec<Disk>,
    /// Counters for rate computation.
    pub counters: Counters,
}

/// Result of parsing a probe.
#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    /// The host exposes `/proc`; here is the sample.
    Sample(Sample),
    /// The host is not Linux (or `/proc` is hidden).
    Unsupported,
}

/// Parse the output of [`PROBE_SCRIPT`]. `None` when the output is not a probe
/// at all (shell error, banner only, truncated).
pub fn parse(out: &str) -> Option<Probe> {
    let mut host = String::new();
    let mut uptime = None;
    let mut load = None;
    let mut mem = None;
    let mut cpu = None;
    let mut net = (0u64, 0u64);
    let mut users: Vec<String> = Vec::new();
    let mut disks: Vec<Disk> = Vec::new();

    for line in out.lines() {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let val = val.trim();
        match key {
            "unsupported" => return Some(Probe::Unsupported),
            "host" => host = val.chars().take(255).collect(),
            "uptime" => uptime = val.parse::<f64>().ok().map(|s| s.max(0.0) as u64),
            "load" => {
                let v: Vec<f32> = val
                    .split_whitespace()
                    .filter_map(|n| n.parse().ok())
                    .collect();
                if let [a, b, c] = v[..] {
                    load = Some([a, b, c]);
                }
            }
            "mem" => {
                let v = numbers(val);
                if let [total, avail] = v[..] {
                    mem = Some((total, avail));
                }
            }
            "cpu" => {
                let v = numbers(val);
                if v.len() >= 4 {
                    let total: u64 = v.iter().take(8).sum();
                    let idle = v[3] + v.get(4).copied().unwrap_or(0);
                    cpu = Some((total.saturating_sub(idle), total));
                }
            }
            "net" => {
                if let [rx, tx] = numbers(val)[..] {
                    net = (rx, tx);
                }
            }
            "user" => {
                if !val.is_empty()
                    && users.len() < MAX_USERS
                    && !users.iter().any(|u| u == val)
                    && val.len() <= 64
                {
                    users.push(val.to_string());
                }
            }
            "disk" => {
                if let Some(d) = parse_disk(val)
                    && disks.len() < MAX_DISKS
                    && !skip_mount(&d.mount)
                    && !disks.iter().any(|x| x.mount == d.mount)
                {
                    disks.push(d);
                }
            }
            _ => {}
        }
    }

    let (cpu_busy, cpu_total) = cpu?;
    let (mem_total_kb, mem_available_kb) = mem?;
    Some(Probe::Sample(Sample {
        host,
        uptime_secs: uptime.unwrap_or(0),
        load,
        mem_total_kb,
        mem_available_kb: mem_available_kb.min(mem_total_kb),
        users,
        disks,
        counters: Counters {
            cpu_busy,
            cpu_total,
            rx_bytes: net.0,
            tx_bytes: net.1,
        },
    }))
}

fn numbers(s: &str) -> Vec<u64> {
    s.split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect()
}

fn parse_disk(val: &str) -> Option<Disk> {
    let mut it = val.splitn(3, ' ');
    let total_kb = it.next()?.parse().ok()?;
    let used_kb = it.next()?.parse().ok()?;
    let mount = it.next()?.trim().to_string();
    if mount.is_empty() || total_kb == 0 {
        return None;
    }
    Some(Disk {
        mount,
        total_kb,
        used_kb,
    })
}

/// Mounts that are the same storage seen twice or are not user-relevant:
/// snap squashfs images, container layers, bind mounts of single files.
fn skip_mount(mount: &str) -> bool {
    mount.starts_with("/snap/")
        || mount.starts_with("/var/lib/docker/")
        || mount.starts_with("/var/lib/containers/")
        || mount.starts_with("/run/")
        || mount.starts_with("/sys/")
        || mount.starts_with("/proc/")
}

/// What the status bar shows.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Host name as the machine reports it.
    pub host: String,
    /// CPU busy share since the previous probe, 0–100. `None` on the first probe.
    pub cpu_percent: Option<f32>,
    /// Memory in use (total minus available) in KiB.
    pub mem_used_kb: u64,
    /// Physical memory in KiB.
    pub mem_total_kb: u64,
    /// Receive rate in bytes/s since the previous probe.
    pub rx_bps: Option<u64>,
    /// Send rate in bytes/s since the previous probe.
    pub tx_bps: Option<u64>,
    /// Seconds since boot.
    pub uptime_secs: u64,
    /// 1, 5 and 15 minute load average.
    pub load: Option<[f32; 3]>,
    /// Distinct logged-in users.
    pub users: Vec<String>,
    /// Real filesystems.
    pub disks: Vec<Disk>,
}

impl Snapshot {
    /// Combine a probe with the previous counters of the same session and the
    /// time between them. Counters that went backwards (reboot, interface
    /// reset) yield `None` rates instead of nonsense.
    pub fn from_samples(cur: &Sample, prev: Option<(&Counters, Duration)>) -> Self {
        let (mut cpu_percent, mut rx_bps, mut tx_bps) = (None, None, None);
        if let Some((p, dt)) = prev {
            let c = &cur.counters;
            if c.cpu_total > p.cpu_total {
                let busy = c.cpu_busy.saturating_sub(p.cpu_busy) as f64;
                let total = (c.cpu_total - p.cpu_total) as f64;
                cpu_percent = Some((busy / total * 100.0).clamp(0.0, 100.0) as f32);
            }
            let secs = dt.as_secs_f64();
            if secs >= 0.2 {
                if c.rx_bytes >= p.rx_bytes {
                    rx_bps = Some(((c.rx_bytes - p.rx_bytes) as f64 / secs) as u64);
                }
                if c.tx_bytes >= p.tx_bytes {
                    tx_bps = Some(((c.tx_bytes - p.tx_bytes) as f64 / secs) as u64);
                }
            }
        }
        Self {
            host: cur.host.clone(),
            cpu_percent,
            mem_used_kb: cur.mem_total_kb.saturating_sub(cur.mem_available_kb),
            mem_total_kb: cur.mem_total_kb,
            rx_bps,
            tx_bps,
            uptime_secs: cur.uptime_secs,
            load: cur.load,
            users: cur.users.clone(),
            disks: cur.disks.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "host=web-01\n\
cpu=1000 10 500 8000 100 0 20 0\n\
uptime=93784.55\n\
load=0.52 0.40 0.31\n\
mem=16318464 9000000\n\
net=5000 7000\n\
user=root\n\
user=ali\n\
user=root\n\
disk=102400000 51200000 /\n\
disk=524288 100000 /boot\n\
disk=1000 500 /snap/core/123\n\
disk=2048000 1024 /mnt/my data\n";

    fn sample(out: &str) -> Sample {
        match parse(out) {
            Some(Probe::Sample(s)) => s,
            other => panic!("not a sample: {other:?}"),
        }
    }

    #[test]
    fn parses_a_full_probe() {
        let s = sample(OUT);
        assert_eq!(s.host, "web-01");
        assert_eq!(s.uptime_secs, 93784);
        assert_eq!(s.load, Some([0.52, 0.40, 0.31]));
        assert_eq!(s.mem_total_kb, 16318464);
        assert_eq!(s.mem_available_kb, 9000000);
        assert_eq!(s.users, vec!["root", "ali"]);
        // busy = total - idle - iowait; total = sum of the 8 fields
        assert_eq!(s.counters.cpu_total, 9630);
        assert_eq!(s.counters.cpu_busy, 9630 - 8000 - 100);
        assert_eq!((s.counters.rx_bytes, s.counters.tx_bytes), (5000, 7000));
        let mounts: Vec<_> = s.disks.iter().map(|d| d.mount.as_str()).collect();
        assert_eq!(mounts, vec!["/", "/boot", "/mnt/my data"]);
    }

    #[test]
    fn unsupported_hosts_are_reported_as_such() {
        assert_eq!(parse("unsupported=1\n"), Some(Probe::Unsupported));
    }

    #[test]
    fn garbage_is_not_a_probe() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("Welcome to Ubuntu\nLast login: today\n"), None);
        // cpu line without memory: truncated output.
        assert_eq!(parse("host=x\ncpu=1 2 3 4 5 6 7 8\n"), None);
    }

    #[test]
    fn available_memory_never_exceeds_total() {
        let s = sample("cpu=1 1 1 1 1 1 1 1\nmem=100 500\n");
        assert_eq!(s.mem_available_kb, 100);
    }

    #[test]
    fn caps_users_and_disks() {
        let mut out = String::from("cpu=1 1 1 1 1 1 1 1\nmem=100 50\n");
        for i in 0..20 {
            out.push_str(&format!("user=u{i}\ndisk=100 10 /d{i}\n"));
        }
        let s = sample(&out);
        assert_eq!(s.users.len(), MAX_USERS);
        assert_eq!(s.disks.len(), MAX_DISKS);
    }

    #[test]
    fn first_probe_has_no_rates() {
        let snap = Snapshot::from_samples(&sample(OUT), None);
        assert_eq!(snap.cpu_percent, None);
        assert_eq!(snap.rx_bps, None);
        assert_eq!(snap.mem_used_kb, 16318464 - 9000000);
    }

    #[test]
    fn rates_from_two_probes() {
        let a = sample("cpu=100 0 100 800 0 0 0 0\nmem=100 50\nnet=1000 2000\n");
        let b = sample("cpu=150 0 150 900 0 0 0 0\nmem=100 50\nnet=3000 2500\n");
        let snap = Snapshot::from_samples(&b, Some((&a.counters, Duration::from_secs(2))));
        // +100 busy of +200 total
        assert_eq!(snap.cpu_percent, Some(50.0));
        assert_eq!(snap.rx_bps, Some(1000));
        assert_eq!(snap.tx_bps, Some(250));
    }

    #[test]
    fn counter_resets_do_not_produce_rates() {
        let a = sample("cpu=500 0 500 9000 0 0 0 0\nmem=100 50\nnet=9000 9000\n");
        let b = sample("cpu=10 0 10 90 0 0 0 0\nmem=100 50\nnet=10 10\n");
        let snap = Snapshot::from_samples(&b, Some((&a.counters, Duration::from_secs(2))));
        assert_eq!(snap.cpu_percent, None);
        assert_eq!(snap.rx_bps, None);
        assert_eq!(snap.tx_bps, None);
    }

    #[test]
    fn probe_script_only_reads() {
        // The script runs unattended on the user's server: no writes, no
        // network, no privilege escalation.
        for bad in ["sudo", ">>", "rm ", "curl", "wget", "nc ", "kill", "chmod"] {
            assert!(!PROBE_SCRIPT.contains(bad), "script contains `{bad}`");
        }
    }
}
