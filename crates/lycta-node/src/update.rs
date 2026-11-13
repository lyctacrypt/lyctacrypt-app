use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::HEXLOWER_PERMISSIVE as HEX;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::tor::Client;

pub const UPDATE_PUBLIC_KEY: &str = "";

pub const UPDATE_MANIFEST_URL: &str =
    "https://github.com/lyctacrypt/LyctaCrypt-App/releases/latest/download/update.json";

const DOMAIN: &[u8] = b"LyctaCrypt/update/v1\n";
const MAX_MANIFEST: usize = 64 * 1024;
const MAX_BINARY: usize = 200 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub target: String,

    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

pub fn enabled() -> bool {
    !UPDATE_PUBLIC_KEY.is_empty()
}

pub fn current_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn parse_version(v: &str) -> Option<[u64; 3]> {
    let core = v.trim().trim_start_matches('v');

    let mut it = core.split('.');
    let out = [
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ];
    it.next().is_none().then_some(out)
}

pub fn is_newer(current: &str, candidate: &str) -> bool {
    match (parse_version(current), parse_version(candidate)) {
        (Some(a), Some(b)) => b > a,
        _ => false,
    }
}

fn signed_bytes(manifest: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(manifest);
    m
}

pub fn verify_manifest(manifest: &[u8], sig_hex: &str, public_key_hex: &str) -> Result<Manifest> {
    let pk: [u8; 32] = HEX
        .decode(public_key_hex.trim().as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid release key"))?;
    let sig: [u8; 64] = HEX
        .decode(sig_hex.trim().as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid update signature"))?;
    VerifyingKey::from_bytes(&pk)
        .map_err(|_| anyhow!("invalid release key"))?
        .verify_strict(&signed_bytes(manifest), &Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("update signature does not match: refusing it"))?;
    let m: Manifest = serde_json::from_slice(manifest).context("malformed update manifest")?;
    if parse_version(&m.version).is_none() {
        bail!("malformed version in update manifest");
    }
    Ok(m)
}

pub fn keygen() -> (String, String) {
    let seed: [u8; 32] = lycta_core::primitives::random_bytes();
    let sk = SigningKey::from_bytes(&seed);
    (HEX.encode(&seed), HEX.encode(sk.verifying_key().as_bytes()))
}

pub fn sign(manifest: &[u8], secret_hex: &str) -> Result<String> {
    let seed: [u8; 32] = HEX
        .decode(secret_hex.trim().as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid secret key"))?;

    serde_json::from_slice::<Manifest>(manifest).context("manifest is not valid")?;
    let sig = SigningKey::from_bytes(&seed).sign(&signed_bytes(manifest));
    Ok(HEX.encode(&sig.to_bytes()))
}

struct Url {
    host: String,
    path: String,
}

fn parse_url(url: &str) -> Result<Url> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("updates only use HTTPS"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || path.chars().any(|c| c.is_control() || c == ' ')
    {
        bail!("invalid update address");
    }
    Ok(Url {
        host: host.to_ascii_lowercase(),
        path: path.to_string(),
    })
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("bad chunked response"))?;
        let line = std::str::from_utf8(&body[..eol])?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| anyhow!("bad chunked response"))?;
        body = &body[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            bail!("truncated response");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

type Response = (u16, Vec<(String, String)>, Vec<u8>);

fn parse_response(raw: &[u8]) -> Result<Response> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("bad response"))?;
    let head = std::str::from_utf8(&raw[..split])?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad response"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let body = &raw[split + 4..];
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let body = if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        decode_chunked(body)?
    } else {
        if let Some(n) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
            if body.len() < n {
                bail!("truncated response");
            }
        }
        body.to_vec()
    };
    Ok((status, headers, body))
}

pub async fn https_get(client: &Client, url: &str, max: usize) -> Result<Vec<u8>> {
    let client = client.isolated_client();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let u = parse_url(&url)?;

        let mut attempt = 0;
        let stream = loop {
            match client
                .isolated_client()
                .connect((u.host.as_str(), 443))
                .await
            {
                Ok(s) => break s,
                Err(e) if attempt >= 3 => return Err(e.into()),
                Err(_) => attempt += 1,
            }
        };
        let name = rustls::pki_types::ServerName::try_from(u.host.clone())
            .map_err(|_| anyhow!("invalid update address"))?;
        let mut tls = connector.connect(name, stream).await?;
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: lyctacrypt\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            u.path, u.host
        );
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match tls.read(&mut buf).await {
                Ok(n) => n,

                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.len() > max + 16 * 1024 {
                bail!("update response too large");
            }
        }
        let (status, headers, body) = parse_response(&raw)?;
        match status {
            200 => {
                if body.len() > max {
                    bail!("update response too large");
                }
                return Ok(body);
            }
            301 | 302 | 303 | 307 | 308 => {
                url = headers
                    .iter()
                    .find(|(k, _)| k == "location")
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| anyhow!("redirect without a target"))?;
            }
            404 => bail!("no update published yet"),
            other => bail!("update server answered {other}"),
        }
    }
    bail!("too many redirects")
}

pub async fn check(client: &Client, current_version: &str) -> Result<Option<Manifest>> {
    if !enabled() {
        bail!("updates are not set up in this build");
    }
    let manifest = https_get(client, UPDATE_MANIFEST_URL, MAX_MANIFEST).await?;
    let sig = https_get(client, &format!("{UPDATE_MANIFEST_URL}.sig"), 1024).await?;
    let m = verify_manifest(&manifest, std::str::from_utf8(&sig)?, UPDATE_PUBLIC_KEY)?;
    Ok(is_newer(current_version, &m.version).then_some(m))
}

pub fn verify_binary(asset: &Asset, data: &[u8]) -> Result<()> {
    if data.len() as u64 != asset.size {
        bail!("downloaded update has the wrong size");
    }
    let digest = HEX.encode(&Sha256::digest(data));
    if !digest.eq_ignore_ascii_case(asset.sha256.trim()) {
        bail!("downloaded update does not match its signed hash: refusing it");
    }
    Ok(())
}

pub async fn download(
    client: &Client,
    manifest: &Manifest,
    name: &str,
    data_dir: &Path,
) -> Result<PathBuf> {
    let target = current_target();
    let asset = manifest
        .assets
        .iter()
        .find(|a| a.target == target && a.name == name)
        .ok_or_else(|| anyhow!("this update has no build for {target}"))?;
    if asset.size as usize > MAX_BINARY {
        bail!("update too large");
    }
    let data = https_get(client, &asset.url, asset.size as usize).await?;
    verify_binary(asset, &data)?;
    let dir = data_dir.join("updates");
    std::fs::create_dir_all(&dir)?;
    let staged = dir.join(format!("{name}-{}", manifest.version));
    std::fs::write(&staged, &data)?;
    Ok(staged)
}

pub fn install(staged: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    let old = exe.with_extension("old");
    let _ = std::fs::remove_file(&old);

    std::fs::rename(&exe, &old).context("could not move the current program aside")?;
    if let Err(e) = std::fs::copy(staged, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(e).context("could not install the update");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(staged);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Vec<u8> {
        br#"{"version":"0.2.0","notes":"fixes","assets":[{"target":"windows-x86_64","name":"lyctacrypt-gui","url":"https://example.org/a.exe","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3}]}"#.to_vec()
    }

    #[test]
    fn only_a_correctly_signed_manifest_is_accepted() {
        let (sk, pk) = keygen();
        let m = manifest();
        let sig = sign(&m, &sk).unwrap();
        assert_eq!(verify_manifest(&m, &sig, &pk).unwrap().version, "0.2.0");

        let (_, other_pk) = keygen();
        assert!(verify_manifest(&m, &sig, &other_pk).is_err());
        let mut changed = m.clone();
        let pos = changed.windows(5).position(|w| w == b"0.2.0").unwrap();
        changed[pos] = b'9';
        assert!(verify_manifest(&changed, &sig, &pk).is_err());
        let mut bad = sig.clone().into_bytes();
        bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
        assert!(verify_manifest(&m, std::str::from_utf8(&bad).unwrap(), &pk).is_err());
        assert!(verify_manifest(&m, "", &pk).is_err());
        assert!(verify_manifest(&m, &sig, "").is_err());
    }

    #[test]
    fn no_downgrades() {
        assert!(is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.9.9", "0.10.0"));
        assert!(is_newer("0.1.0", "v1.0.0"));
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.1.9"));
        assert!(!is_newer("0.2.0", "nonsense"));
        assert!(!is_newer("0.2.0", "0.3.0-beta"));
    }

    #[test]
    fn binary_must_match_the_signed_hash() {
        let (sk, pk) = keygen();
        let m = manifest();
        let parsed = verify_manifest(&m, &sign(&m, &sk).unwrap(), &pk).unwrap();
        assert!(verify_binary(&parsed.assets[0], b"abc").is_ok());
        assert!(verify_binary(&parsed.assets[0], b"abd").is_err());
        assert!(verify_binary(&parsed.assets[0], b"abcd").is_err());
    }

    #[test]
    fn http_parsing() {
        let (s, h, b) =
            parse_response(b"HTTP/1.1 302 Found\r\nLocation: https://x.example/y\r\n\r\n").unwrap();
        assert_eq!(s, 302);
        assert_eq!(h[0], ("location".into(), "https://x.example/y".into()));
        assert!(b.is_empty());
        let (s, _, b) = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((s, b.as_slice()), (200, b"abcde".as_slice()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").is_err());
        assert!(parse_url("http://example.org/x").is_err());
        assert!(parse_url("https://exa mple.org/x").is_err());
        assert_eq!(
            parse_url("https://Example.org/a/b").unwrap().host,
            "example.org"
        );
    }
}
