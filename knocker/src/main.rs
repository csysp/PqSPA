#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::Parser;
use hmac::{Hmac, Mac};
use pqcrypto_mlkem::mlkem768 as kem;
use pqcrypto_traits::kem::{Ciphertext as CtTrait, PublicKey as PkTrait, SharedSecret as SsTrait};
use sha2::Sha256;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, serde::Deserialize)]
struct Config {
    router_host: String,
    spa_port: u16,
    wg_port: u16,
    kem_pub_b64: String,
    psk_b64: String,
}

#[derive(Parser, Debug)]
#[command(name = "spa-knocker", version)]
struct Cli {
    /// Path to client config JSON
    #[arg(long)]
    config: Option<PathBuf>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

fn default_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(app) = std::env::var("APPDATA") {
            let p = PathBuf::from(app).join("PqSPA").join("spa-knocker.json");
            if p.exists() { return Some(p); }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            let p = PathBuf::from(xdg).join("spa-knocker.json");
            if p.exists() { return Some(p); }
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".config").join("spa-knocker.json");
            if p.exists() { return Some(p); }
        }
    }
    let local = PathBuf::from("spa-knocker.json");
    if local.exists() { Some(local) } else { None }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = cli.config.or_else(default_config_path)
        .ok_or_else(|| anyhow!("config not found; pass --config"))?;
    let cfg_data = fs::read_to_string(&cfg_path)
        .with_context(|| format!("read {}", cfg_path.display()))?;
    let cfg: Config = serde_json::from_str(&cfg_data)?;
    let _wg_port = cfg.wg_port; // satisfy dead_code lint

    let pub_bytes = STANDARD.decode(cfg.kem_pub_b64.trim())?;
    let psk = STANDARD.decode(cfg.psk_b64.trim())?;
    if psk.len() != 32 {
        return Err(anyhow!("psk must be 32 bytes"));
    }
    let pk =
        <kem::PublicKey as PkTrait>::from_bytes(&pub_bytes).map_err(|_| anyhow!("bad pubkey"))?;

    let addr = format!("{}:{}", cfg.router_host, cfg.spa_port);
    let mut addrs = addr.to_socket_addrs()?;
    let dst = addrs.next().ok_or_else(|| anyhow!("resolve {}", addr))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(dst)?;
    // derive local IPv4 (still included in packet, not in HMAC)
    let local = sock.local_addr()?;
    let local_v4 = match local {
        SocketAddr::V4(v4) => v4,
        _ => return Err(anyhow!("local address not IPv4")),
    };
    let client_ip_u32 = u32::from_be_bytes(local_v4.ip().octets());

    // build fields
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!(e))?;
    let ts = now_unix();

    // encapsulate (crate returns (SharedSecret, Ciphertext))
    let (shared, ct) = kem::encapsulate(&pk);
    let ct_bytes = <kem::Ciphertext as CtTrait>::as_bytes(&ct);
    let key = <kem::SharedSecret as SsTrait>::as_bytes(&shared);

    // HMAC over PSK || ver || nonce || ts (client_ip is NOT included)
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| anyhow!("hmac key"))?;
    mac.update(&psk);
    mac.update(&[1u8]);
    mac.update(&nonce);
    mac.update(&ts.to_be_bytes());
    let tag = mac.finalize().into_bytes();

    // packet v1: u8 ver(1) | u16 ct_len | ct | nonce(16) | ts(i64) | client_ip(u32) | tag(32)
    let ct_len = ct_bytes.len();
    if ct_len > u16::MAX as usize {
        return Err(anyhow!("ct too large"));
    }
    let mut pkt = Vec::with_capacity(1 + 2 + ct_len + 16 + 8 + 4 + 32);
    pkt.push(1u8);
    pkt.extend_from_slice(&(ct_len as u16).to_be_bytes());
    pkt.extend_from_slice(ct_bytes);
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ts.to_be_bytes());
    pkt.extend_from_slice(&client_ip_u32.to_be_bytes());
    pkt.extend_from_slice(&tag);

    sock.send(&pkt)?;
    sock.set_read_timeout(Some(Duration::from_millis(1000)))?;
    let mut buf = [0u8; 16];
    match sock.recv(&mut buf) {
        Ok(n) if n >= 2 && &buf[..2] == b"OK" => {
            println!("OK.");
        }
        _ => {
            println!("Knock sent. If valid, port should open shortly.");
        }
    }
    Ok(())
}
