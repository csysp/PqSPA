#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pqcrypto_mlkem::mlkem768 as kem;
use pqcrypto_traits::kem::{
    Ciphertext as CtTrait, PublicKey as PkTrait, SecretKey as SkTrait, SharedSecret as SsTrait,
};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

// Protocol constants (Kyber/ML-KEM-768)
const PROTO_VER: u8 = 1;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 32;
// Kyber768 ciphertext size in bytes (ML-KEM-768)
const CT_LEN_KYBER768: usize = 1088;

// Replay cache with O(1) membership and TTL-based purge
struct ReplayCache {
    ttl: Duration,
    set: HashSet<(IpAddr, [u8; NONCE_LEN], i64)>,
    order: VecDeque<(Instant, IpAddr, [u8; NONCE_LEN], i64)>,
    cap: usize,
}

impl ReplayCache {
    fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl,
            set: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn purge_expired(&mut self, now: Instant) {
        while let Some((t, ip, n, ts)) = self.order.front().cloned() {
            if now.duration_since(t) > self.ttl {
                self.order.pop_front();
                self.set.remove(&(ip, n, ts));
            } else {
                break;
            }
        }
        // Hard cap: if exceeded, drop oldest entries
        while self.order.len() > self.cap {
            if let Some((_, ip, n, ts)) = self.order.pop_front() {
                self.set.remove(&(ip, n, ts));
            } else {
                break;
            }
        }
    }
    fn seen_or_insert(
        &mut self,
        ip: IpAddr,
        nonce: [u8; NONCE_LEN],
        ts: i64,
        now: Instant,
    ) -> bool {
        if self.set.contains(&(ip, nonce, ts)) {
            return true;
        }
        self.set.insert((ip, nonce, ts));
        self.order.push_back((now, ip, nonce, ts));
        false
    }
}

#[derive(Parser, Debug)]
#[command(name = "spa-doorman", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a Kyber/ML-KEM-768 keypair
    GenKeys {
        /// Private key output path (raw bytes)
        #[arg(long)]
        priv_out: PathBuf,
        /// Public key output path (raw bytes)
        #[arg(long)]
        pub_out: PathBuf,
    },

    /// Run SPA daemon
    Run {
        /// Listen address, e.g. 0.0.0.0:62201
        #[arg(long, default_value = "0.0.0.0:62201")]
        listen: String,
        /// Path to KEM private key (raw bytes)
        #[arg(long, default_value = "/etc/spa/priv.bin")]
        kem_priv: PathBuf,
        /// Path to PSK (32 bytes)
        #[arg(long, default_value = "/etc/spa/psk.bin")]
        psk_file: PathBuf,
        /// Allow window for port opening (seconds)
        #[arg(long, default_value_t = 45)]
        open_secs: u64,
        /// Acceptable time skew for knocks (seconds)
        #[arg(long, default_value_t = 30)]
        window_secs: i64,
        /// nftables family (e.g., inet)
        #[arg(long, default_value = "inet")]
        nft_family: String,
        /// nftables table (e.g., fw4 on OpenWRT)
        #[arg(long, default_value = "fw4")]
        nft_table: String,
        /// nftables set name to receive allowed source IPs
        #[arg(long, default_value = "wg_spa_allow")]
        nft_set: String,
        /// Obfuscate client_ip in logs (hash)
        #[arg(long, default_value_t = false)]
        obfuscate_ip: bool,
        /// Max knocks per second per IP
        #[arg(long, default_value_t = 10)]
        rate_pps: u32,
        /// Burst size for per-IP limiter
        #[arg(long, default_value_t = 20)]
        rate_burst: u32,
        /// Optional log file path (JSONL)
        #[arg(long)]
        log_file: Option<PathBuf>,
        /// Increase verbosity (developer runs)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
        /// Quiet mode (suppress info logs)
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },

    /// Validate nftables family/table/set exist
    NftValidate {
        /// nftables family (e.g., inet)
        #[arg(long, default_value = "inet")]
        nft_family: String,
        /// nftables table (e.g., fw4)
        #[arg(long, default_value = "fw4")]
        nft_table: String,
        /// nftables set to check
        #[arg(long, default_value = "wg_spa_allow")]
        nft_set: String,
    },

    /// Run SPA + UDP proxy (cross-platform)
    /// Validates SPA knocks and, for allowed client IPs, proxies UDP between clients and an upstream service.
    RunProxy {
        /// SPA listen address, e.g. 0.0.0.0:62201
        #[arg(long, default_value = "0.0.0.0:62201")]
        spa_listen: String,
        /// Path to KEM private key (raw bytes)
        #[arg(long, default_value = "/etc/spa/priv.bin")]
        kem_priv: PathBuf,
        /// Path to PSK (32 bytes)
        #[arg(long, default_value = "/etc/spa/psk.bin")]
        psk_file: PathBuf,
        /// Allow window for port opening (seconds)
        #[arg(long, default_value_t = 45)]
        open_secs: u64,
        /// Acceptable time skew for knocks (seconds)
        #[arg(long, default_value_t = 30)]
        window_secs: i64,
        /// UDP listen address to proxy on (public service port), e.g. 0.0.0.0:51820
        #[arg(long)]
        proxy_listen: String,
        /// Upstream service address to forward to, e.g. 127.0.0.1:51820
        #[arg(long)]
        upstream: String,
    },
}

#[derive(Debug, serde::Serialize)]
struct LogLine<'a> {
    ts: i64,
    client_ip: &'a str,
    decision: &'a str,
    reason: &'a str,
    opens_for_secs: u64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    Ok(b)
}

fn write_file(path: &PathBuf, data: &[u8], mode: Option<u32>) -> Result<()> {
    if let Some(m) = mode {
        // best-effort set umask'd perms after write
        let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
        f.write_all(data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(m))?;
        }
        Ok(())
    } else {
        fs::write(path, data)?;
        Ok(())
    }
}

fn gen_keys(priv_out: PathBuf, pub_out: PathBuf) -> Result<()> {
    let (pk, sk) = kem::keypair();
    write_file(&priv_out, SkTrait::as_bytes(&sk), Some(0o600))?;
    write_file(&pub_out, PkTrait::as_bytes(&pk), Some(0o644))?;
    eprintln!(
        "generated ML-KEM-768 keypair: priv={}, pub={}",
        priv_out.display(),
        pub_out.display()
    );
    Ok(())
}

fn ensure_nft_set(family: &str, table: &str, set_name: &str) -> Result<()> {
    // Fail-fast verification that the table and target set exist.
    let ok_table = std::process::Command::new("nft")
        .args(["list", "table", family, table])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let ok_set = std::process::Command::new("nft")
        .args(["list", "set", family, table, set_name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !(ok_table && ok_set) {
        return Err(SpaError::NftMissing.into());
    }
    Ok(())
}

fn add_allow_set_entry(
    family: &str,
    table: &str,
    set_name: &str,
    client_ip: Ipv4Addr,
    open_secs: u64,
) -> Result<()> {
    // add element to set with timeout
    let elem = format!("{{ {} timeout {}s }}", client_ip, open_secs);
    let status = std::process::Command::new("nft")
        .args(["add", "element", family, table, set_name, &elem])
        .status()
        .context("nft add element")?;
    if !status.success() {
        return Err(anyhow!("nft add element failed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_daemon(
    listen: String,
    kem_priv: PathBuf,
    psk_file: PathBuf,
    open_secs: u64,
    window_secs: i64,
    nft_family: String,
    nft_table: String,
    nft_set: String,
    obfuscate_ip: bool,
    rate_pps: u32,
    rate_burst: u32,
    log_file: Option<PathBuf>,
    verbose: u8,
    quiet: bool,
) -> Result<()> {
    let sock = UdpSocket::bind(&listen).with_context(|| format!("bind {}", listen))?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let kem_priv = read_file(&kem_priv)?;
    let psk = read_file(&psk_file)?;
    if psk.len() != 32 {
        return Err(anyhow!("psk must be 32 bytes"));
    }
    let sk =
        <kem::SecretKey as SkTrait>::from_bytes(&kem_priv).map_err(|_| anyhow!("bad privkey"))?;

    ensure_nft_set(&nft_family, &nft_table, &nft_set)?;

    let mut rl = RateLimiter::new(rate_pps, rate_burst);
    let mut logger = Logger::new(log_file, quiet)?;

    let mut rc = ReplayCache::new(Duration::from_secs((open_secs + 2 * (window_secs as u64)).max(60)), 4096);
    let mut last_purge = Instant::now();

    loop {
        let mut buf = [0u8; 2048 + CT_LEN_KYBER768];
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if !rl.allow(peer.ip()) {
                    logger.log_drop(peer.ip(), "rate_limited", 0, obfuscate_ip);
                    continue;
                }
                if let Err(e) = handle_packet(
                    &sock,
                    &buf[..n],
                    peer,
                    &sk,
                    &psk,
                    open_secs,
                    window_secs,
                    &nft_family,
                    &nft_table,
                    &nft_set,
                    &mut rc,
                ) {
                    let reason = if verbose > 0 { format!("{}", e) } else { "error".to_string() };
                    logger.log_drop(peer.ip(), &reason, 0, obfuscate_ip);
                } else {
                    logger.log_allow(peer.ip(), "valid", open_secs, obfuscate_ip);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // periodic maintenance
                let now = Instant::now();
                if now.duration_since(last_purge) > Duration::from_secs(5) {
                    rc.purge_expired(now);
                    last_purge = now;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[derive(Error, Debug)]
enum SpaError {
    #[error("invalid packet version")]
    BadVersion,
    #[error("ciphertext length")]
    BadCtLen,
    #[error("timestamp skew too large")]
    BadTime,
    #[error("replay detected")]
    Replay,
    #[error("nftables table/set not found")]
    NftMissing,
}

// Simple per-IP token bucket limiter
struct RateLimiter {
    map: HashMap<IpAddr, (u32, Instant)>,
    pps: u32,
    burst: u32,
}
impl RateLimiter {
    fn new(pps: u32, burst: u32) -> Self { Self { map: HashMap::new(), pps, burst } }
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let e = self.map.entry(ip).or_insert((self.burst, now));
        let elapsed = now.duration_since(e.1).as_secs_f64();
        let refill = (elapsed * self.pps as f64) as u32;
        let mut tokens = e.0.saturating_add(refill);
        if tokens > self.burst { tokens = self.burst; }
        e.1 = now;
        if tokens == 0 { e.0 = 0; return false; }
        e.0 = tokens - 1; true
    }
}

struct Logger {
    file: Option<std::fs::File>,
    quiet: bool,
}
impl Logger {
    fn new(path: Option<PathBuf>, quiet: bool) -> Result<Self> {
        if let Some(p) = path { Ok(Self{ file: Some(std::fs::File::create(p)? ), quiet }) } else { Ok(Self{ file: None, quiet }) }
    }
    fn hash_ip(ip: IpAddr) -> String {
        use std::hash::{Hash, Hasher};
        let mut s = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut s);
        format!("{:x}", s.finish())
    }
    fn log(&mut self, ip: IpAddr, decision: &str, reason: &str, secs: u64, obf: bool) {
        if self.quiet && decision == "allow" { return; }
        let ts = now_unix();
        let cip = if obf { Self::hash_ip(ip) } else { ip.to_string() };
        let line = format!("{{\"ts\":{},\"client_ip\":\"{}\",\"decision\":\"{}\",\"reason\":\"{}\",\"opens_for_secs\":{}}}\n", ts, cip, decision, reason, secs);
        if let Some(f) = self.file.as_mut() { let _ = f.write_all(line.as_bytes()); } else { eprintln!("{}", line.trim_end()); }
    }
    fn log_allow(&mut self, ip: IpAddr, reason: &str, secs: u64, obf: bool) { self.log(ip, "allow", reason, secs, obf); }
    fn log_drop(&mut self, ip: IpAddr, reason: &str, secs: u64, obf: bool) { self.log(ip, "drop", reason, secs, obf); }
}

#[allow(clippy::too_many_arguments)]
fn handle_packet(
    sock: &UdpSocket,
    pkt: &[u8],
    peer: SocketAddr,
    sk: &kem::SecretKey,
    psk: &[u8],
    open_secs: u64,
    window_secs: i64,
    nft_family: &str,
    nft_table: &str,
    nft_set: &str,
    rc: &mut ReplayCache,
) -> Result<()> {
    let (peer_ip, peer_v4_opt) = match peer {
        SocketAddr::V4(v4) => (IpAddr::V4(*v4.ip()), Some(*v4.ip())),
        SocketAddr::V6(v6) => (IpAddr::V6(*v6.ip()), None),
    };

    let mut off = 0;
    if pkt.len() < 1 + 2 + NONCE_LEN + 8 + 4 + TAG_LEN {
        return Err(anyhow!("short packet"));
    }
    let ver = pkt[off];
    off += 1;
    if ver != PROTO_VER {
        return Err(SpaError::BadVersion.into());
    }
    let ct_len = u16::from_be_bytes([pkt[off], pkt[off + 1]]) as usize;
    off += 2;
    if ct_len > CT_LEN_KYBER768 || off + ct_len + NONCE_LEN + 8 + 4 + TAG_LEN > pkt.len() {
        return Err(SpaError::BadCtLen.into());
    }
    let ct_bytes = &pkt[off..off + ct_len];
    off += ct_len;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&pkt[off..off + NONCE_LEN]);
    off += NONCE_LEN;
    let ts = i64::from_be_bytes(pkt[off..off + 8].try_into().unwrap());
    off += 8;
    let _client_ip_u32 = u32::from_be_bytes(pkt[off..off + 4].try_into().unwrap());
    off += 4;
    let tag = &pkt[off..off + TAG_LEN];

    // decapsulate
    let ct = <kem::Ciphertext as CtTrait>::from_bytes(ct_bytes).map_err(|_| anyhow!("ct"))?;
    let shared = kem::decapsulate(&ct, sk);
    let key = <kem::SharedSecret as SsTrait>::as_bytes(&shared);

    // verify HMAC over psk || ver || nonce || ts
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| anyhow!("hmac key"))?;
    mac.update(psk);
    mac.update(&[ver]);
    mac.update(&nonce);
    mac.update(&ts.to_be_bytes());
    mac.verify_slice(tag).map_err(|_| anyhow!("bad tag"))?;

    // time window check
    let now = now_unix();
    if (now - ts).abs() > window_secs {
        return Err(SpaError::BadTime.into());
    }

    // replay detection
    let nowi = Instant::now();
    let is_replay = rc.seen_or_insert(peer_ip, nonce, ts, nowi);
    if is_replay {
        return Err(SpaError::Replay.into());
    }

    // add to nft set with timeout
    if let Some(v4) = peer_v4_opt {
        add_allow_set_entry(nft_family, nft_table, nft_set, v4, open_secs)?;
    } else {
        return Err(anyhow!("ipv6 set not configured"));
    }

    // optional friendly ack (best effort)
    let _ = sock.send_to(b"OK\n", peer);

    eprintln!(
        "{{\"ts\":{},\"client_ip\":\"{}\",\"decision\":\"allow\",\"reason\":\"valid\",\"opens_for_secs\":{}}}",
        now, peer_ip, open_secs
    );

    Ok(())
}

// Cross-platform proxy backend -------------------------------------------------

fn run_proxy_daemon(
    spa_listen: String,
    kem_priv: PathBuf,
    psk_file: PathBuf,
    open_secs: u64,
    window_secs: i64,
    proxy_listen: String,
    upstream: String,
) -> Result<()> {
    let allowed: Arc<Mutex<HashMap<IpAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let rc = Arc::new(Mutex::new(ReplayCache::new(
        Duration::from_secs((open_secs + 2 * (window_secs as u64)).max(60)),
        4096,
    )));

    let kem_priv_bytes = read_file(&kem_priv)?;
    let psk = read_file(&psk_file)?;
    if psk.len() != 32 {
        return Err(anyhow!("psk must be 32 bytes"));
    }
    let sk = <kem::SecretKey as SkTrait>::from_bytes(&kem_priv_bytes)
        .map_err(|_| anyhow!("bad privkey"))?;

    // SPA listener thread
    let allowed_spa = allowed.clone();
    let rc_spa = rc.clone();
    let spa_thr = thread::spawn(move || -> Result<()> {
        let sock = UdpSocket::bind(&spa_listen).with_context(|| format!("bind {}", spa_listen))?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        let mut last_purge = Instant::now();
        loop {
            let mut buf = [0u8; 2048 + CT_LEN_KYBER768];
            match sock.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    if let Err(e) = handle_packet_proxy(
                        &sock,
                        &buf[..n],
                        peer,
                        &sk,
                        &psk,
                        open_secs,
                        window_secs,
                        &allowed_spa,
                        &rc_spa,
                    ) {
                        eprintln!(
                            "{{\"ts\":{},\"client_ip\":\"{}\",\"decision\":\"drop\",\"reason\":\"{}\",\"opens_for_secs\":0}}",
                            now_unix(), peer.ip(), e
                        );
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now.duration_since(last_purge) > Duration::from_secs(5) {
                        if let Ok(mut r) = rc_spa.lock() {
                            r.purge_expired(now);
                        }
                        if let Ok(mut m) = allowed_spa.lock() {
                            m.retain(|_, exp| *exp > now);
                        }
                        last_purge = now;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    });

    // UDP proxy main loop
    let proxy_sock = UdpSocket::bind(&proxy_listen)
        .with_context(|| format!("bind {}", proxy_listen))?;
    proxy_sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    let upstream_addr: SocketAddr = {
        let mut it = upstream
            .to_socket_addrs()
            .with_context(|| format!("resolve {}", upstream))?;
        it.next().ok_or_else(|| anyhow!("resolve {}", upstream))?
    };

    let mut sessions: HashMap<(IpAddr, u16), (std::sync::Arc<UdpSocket>, Instant)> =
        HashMap::new();
    let mut last_sweep = Instant::now();

    loop {
        let mut buf = [0u8; 65535];
        match proxy_sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let (src_ip, src_port) = match src {
                    SocketAddr::V4(v4) => (IpAddr::V4(*v4.ip()), v4.port()),
                    SocketAddr::V6(v6) => (IpAddr::V6(*v6.ip()), v6.port()),
                };
                let nowi = Instant::now();
                let allowed_until = allowed
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&src_ip).cloned())
                    .unwrap_or(Instant::now() - Duration::from_secs(1));
                if nowi > allowed_until {
                    continue;
                }

                let entry = sessions.entry((src_ip, src_port)).or_insert_with(|| {
                    let us = UdpSocket::bind("0.0.0.0:0").expect("bind upstream sock");
                    us.connect(upstream_addr).expect("connect upstream");
                    us.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    let us_arc = std::sync::Arc::new(us);
                    let us_clone = us_arc.clone();
                    let proxy_tx = proxy_sock.try_clone().expect("clone proxy sock");
                    let client_addr = match src_ip { IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, src_port)), IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), src_port) };
                    thread::spawn(move || {
                        let mut rbuf = [0u8; 65535];
                        loop {
                            match us_clone.recv(&mut rbuf) {
                                Ok(m) => {
                                    let _ = proxy_tx.send_to(&rbuf[..m], client_addr);
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    thread::sleep(Duration::from_millis(50));
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    (us_arc, Instant::now() + Duration::from_secs(60))
                });
                let (us_arc, exp) = entry;
                let _ = us_arc.send(&buf[..n]);
                *exp = Instant::now() + Duration::from_secs(60);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let nowi = Instant::now();
                if nowi.duration_since(last_sweep) > Duration::from_secs(5) {
                    sessions.retain(|_, (_, exp)| *exp > nowi);
                    last_sweep = nowi;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    // let _ = spa_thr.join();
}

#[allow(clippy::too_many_arguments)]
fn handle_packet_proxy(
    sock: &UdpSocket,
    pkt: &[u8],
    peer: SocketAddr,
    sk: &kem::SecretKey,
    psk: &[u8],
    open_secs: u64,
    window_secs: i64,
    allowed: &Arc<Mutex<HashMap<IpAddr, Instant>>>,
    rc: &Arc<Mutex<ReplayCache>>,
) -> Result<()> {
    let (peer_ip, _peer_v4_opt) = match peer {
        SocketAddr::V4(v4) => (IpAddr::V4(*v4.ip()), Some(*v4.ip())),
        SocketAddr::V6(v6) => (IpAddr::V6(*v6.ip()), None),
    };

    let mut off = 0;
    if pkt.len() < 1 + 2 + NONCE_LEN + 8 + 4 + TAG_LEN {
        return Err(anyhow!("short packet"));
    }
    let ver = pkt[off];
    off += 1;
    if ver != PROTO_VER {
        return Err(SpaError::BadVersion.into());
    }
    let ct_len = u16::from_be_bytes([pkt[off], pkt[off + 1]]) as usize;
    off += 2;
    if ct_len > CT_LEN_KYBER768 || off + ct_len + NONCE_LEN + 8 + 4 + TAG_LEN > pkt.len() {
        return Err(SpaError::BadCtLen.into());
    }
    let ct_bytes = &pkt[off..off + ct_len];
    off += ct_len;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&pkt[off..off + NONCE_LEN]);
    off += NONCE_LEN;
    let ts = i64::from_be_bytes(pkt[off..off + 8].try_into().unwrap());
    off += 8;
    let _client_ip_u32 = u32::from_be_bytes(pkt[off..off + 4].try_into().unwrap());
    off += 4;
    let tag = &pkt[off..off + TAG_LEN];

    let ct = <kem::Ciphertext as CtTrait>::from_bytes(ct_bytes).map_err(|_| anyhow!("ct"))?;
    let shared = kem::decapsulate(&ct, sk);
    let key = <kem::SharedSecret as SsTrait>::as_bytes(&shared);

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| anyhow!("hmac key"))?;
    mac.update(psk);
    mac.update(&[ver]);
    mac.update(&nonce);
    mac.update(&ts.to_be_bytes());
    mac.verify_slice(tag).map_err(|_| anyhow!("bad tag"))?;

    let now = now_unix();
    if (now - ts).abs() > window_secs {
        return Err(SpaError::BadTime.into());
    }

    let nowi = Instant::now();
    {
        let mut r = rc.lock().map_err(|_| anyhow!("replay cache lock"))?;
        let is_replay = r.seen_or_insert(peer_ip, nonce, ts, nowi);
        if is_replay {
            return Err(SpaError::Replay.into());
        }
    }

    if let Ok(mut m) = allowed.lock() {
        m.insert(peer_ip, Instant::now() + Duration::from_secs(open_secs));
    }

    let _ = sock.send_to(b"OK\n", peer);
    eprintln!(
        "{{\"ts\":{},\"client_ip\":\"{}\",\"decision\":\"allow\",\"reason\":\"valid\",\"opens_for_secs\":{}}}",
        now, peer_ip, open_secs
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::GenKeys { priv_out, pub_out } => gen_keys(priv_out, pub_out),
        Command::Run {
            listen,
            kem_priv,
            psk_file,
            open_secs,
            window_secs,
            nft_family,
            nft_table,
            nft_set,
            obfuscate_ip,
            rate_pps,
            rate_burst,
            log_file,
            verbose,
            quiet,
            ..
        } => run_daemon(
            listen,
            kem_priv,
            psk_file,
            open_secs,
            window_secs,
            nft_family,
            nft_table,
            nft_set,
            obfuscate_ip,
            rate_pps,
            rate_burst,
            log_file,
            verbose,
            quiet,
        ),
        Command::NftValidate { nft_family, nft_table, nft_set } => {
            if ensure_nft_set(&nft_family, &nft_table, &nft_set).is_ok() {
                println!("ok");
                Ok(())
            } else {
                Err(anyhow!("nft missing: ensure family/table/set exist"))
            }
        }
        Command::RunProxy {
            spa_listen,
            kem_priv,
            psk_file,
            open_secs,
            window_secs,
            proxy_listen,
            upstream,
        } => run_proxy_daemon(
            spa_listen,
            kem_priv,
            psk_file,
            open_secs,
            window_secs,
            proxy_listen,
            upstream,
        ),
    }
}

