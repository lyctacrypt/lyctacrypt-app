use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Obfs4,
    Snowflake,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Obfs4 => "obfs4",
            Kind::Snowflake => "snowflake",
        }
    }

    fn programs(self) -> &'static [&'static str] {
        match self {
            Kind::Obfs4 => &["lyrebird", "obfs4proxy"],
            Kind::Snowflake => &["snowflake-client", "lyrebird"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Current {
    Direct,
    Bridges { protocol: String, count: usize },
}

pub fn current(data_dir: &Path) -> Current {
    match crate::tor::TorOptions::load_files(data_dir) {
        Ok(o) if !o.bridges.is_empty() => Current::Bridges {
            protocol: o
                .pt_protocols
                .first()
                .cloned()
                .unwrap_or_else(|| "plain".into()),
            count: o.bridges.len(),
        },
        _ => Current::Direct,
    }
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Desktop").join("Tor Browser"));
        roots.push(home.join("OneDrive").join("Desktop").join("Tor Browser"));
        roots.push(home.join("Downloads").join("Tor Browser"));
        roots.push(home.join("tor-browser"));
        roots.push(home.join(".local/share/torbrowser/tbb/x86_64/tor-browser"));
        roots.push(home.join(".local/share/torbrowser/tbb/aarch64/tor-browser"));
        roots.push(home.join("Applications/Tor Browser.app"));
    }
    if let Some(d) = dirs::data_local_dir() {
        roots.push(d.join("Tor Browser"));
    }
    if let Some(d) = dirs::desktop_dir() {
        roots.push(d.join("Tor Browser"));
    }
    roots.push(PathBuf::from("/Applications/Tor Browser.app"));
    let tails = [
        "Browser/TorBrowser/Tor/PluggableTransports",
        "Contents/MacOS/Tor/PluggableTransports",
    ];
    roots
        .iter()
        .flat_map(|r| tails.iter().map(move |t| r.join(t)))
        .collect()
}

pub fn find_tor_browser() -> Option<PathBuf> {
    candidate_dirs().into_iter().find(|d| d.is_dir())
}

pub fn find_program(dir: &Path, kind: Kind) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    let stem = |p: &Path| {
        p.file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
    };

    kind.programs()
        .iter()
        .find_map(|n| files.iter().find(|p| stem(p) == *n).cloned())
}

fn pt_config(dir: &Path) -> Result<serde_json::Value> {
    const INNER: &str = "chrome/toolkit/content/global/pt_config.json";
    let raw = match std::fs::read(dir.join("pt_config.json")) {
        Ok(raw) => raw,
        Err(_) => {
            let archive = dir
                .ancestors()
                .flat_map(|a| [a.join("omni.ja"), a.join("Resources").join("omni.ja")])
                .find(|p| p.is_file())
                .ok_or_else(|| anyhow!("Tor Browser's bridge list was not found"))?;
            let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?)
                .context("unreadable Tor Browser archive")?;
            let mut entry = zip
                .by_name(INNER)
                .context("Tor Browser's bridge list was not found")?;
            if entry.size() > 1024 * 1024 {
                bail!("unexpected bridge list size");
            }
            let mut raw = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut raw)?;
            raw
        }
    };
    serde_json::from_slice(&raw).context("unreadable bridge list")
}

pub fn builtin_bridges(dir: &Path, kind: Kind) -> Result<Vec<String>> {
    let json = pt_config(dir)?;
    let lines: Vec<String> = json
        .get("bridges")
        .and_then(|b| b.get(kind.name()))
        .and_then(|l| l.as_array())
        .map(|l| {
            l.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if lines.is_empty() {
        bail!("Tor Browser has no built-in {} bridges", kind.name());
    }
    Ok(lines)
}

pub fn validate_lines(lines: &[String]) -> Result<()> {
    if lines.is_empty() {
        bail!("no bridge lines");
    }
    for l in lines {
        l.parse::<arti_client::config::BridgeConfigBuilder>()
            .map_err(|e| anyhow!("invalid bridge line: {e}"))?;
    }
    Ok(())
}

pub fn parse_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.strip_prefix("Bridge ")
                .or_else(|| l.strip_prefix("bridge "))
                .unwrap_or(l)
                .trim()
                .to_string()
        })
        .collect()
}

pub fn protocol_of(line: &str) -> Option<String> {
    let first = line.split_whitespace().next()?;
    (!first.contains(':') && !first.contains('.')).then(|| first.to_ascii_lowercase())
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn save(data_dir: &Path, lines: &[String], program: Option<&Path>) -> Result<()> {
    validate_lines(lines)?;
    let mut protocols: Vec<String> = lines.iter().filter_map(|l| protocol_of(l)).collect();
    protocols.sort();
    protocols.dedup();
    match (program, protocols.is_empty()) {
        (None, false) => bail!(
            "these bridges need a transport program ({})",
            protocols.join(", ")
        ),
        (Some(p), _) if !p.is_file() => bail!("transport program not found"),
        _ => {}
    }
    std::fs::create_dir_all(data_dir)?;
    write_private(&data_dir.join("bridges.txt"), &(lines.join("\n") + "\n"))?;
    let transport = data_dir.join("transport.txt");
    match program {
        Some(p) if !protocols.is_empty() => write_private(
            &transport,
            &format!("{}\n{}\n", p.display(), protocols.join("\n")),
        )?,
        _ => {
            let _ = std::fs::remove_file(&transport);
        }
    }
    Ok(())
}

pub fn use_tor_browser(data_dir: &Path, kind: Kind) -> Result<usize> {
    let dir = find_tor_browser()
        .ok_or_else(|| anyhow!("Tor Browser was not found. Install it, or add bridges by hand."))?;
    let program = find_program(&dir, kind)
        .ok_or_else(|| anyhow!("Tor Browser's {} transport was not found", kind.name()))?;
    let lines = builtin_bridges(&dir, kind)?;
    save(data_dir, &lines, Some(&program))?;
    Ok(lines.len())
}

pub fn clear(data_dir: &Path) -> Result<()> {
    for f in ["bridges.txt", "transport.txt"] {
        let p = data_dir.join(f);
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBFS4: &str = "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0";

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "lycta-bridges-{name}-{}",
            u64::from_le_bytes(lycta_core::primitives::random_bytes())
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_pasted_lines() {
        let text = format!("# comment\n\nBridge {OBFS4}\n192.0.2.1:9001 0123456789ABCDEF0123456789ABCDEF01234567\n");
        let lines = parse_lines(&text);
        assert_eq!(lines.len(), 2);
        assert_eq!(protocol_of(&lines[0]).as_deref(), Some("obfs4"));
        assert_eq!(protocol_of(&lines[1]), None);
        assert!(validate_lines(&lines).is_ok());
        assert!(validate_lines(&["not a bridge".into()]).is_err());
        assert!(validate_lines(&[]).is_err());
    }

    #[test]
    fn reads_a_tor_browser_folder_and_saves_the_choice() {
        let tb = temp("tb");
        let exe = tb.join(if cfg!(windows) {
            "lyrebird.exe"
        } else {
            "lyrebird"
        });
        std::fs::write(&exe, b"x").unwrap();
        std::fs::write(
            tb.join("pt_config.json"),
            format!(r#"{{"bridges":{{"obfs4":["{OBFS4}"],"snowflake":[]}}}}"#),
        )
        .unwrap();
        assert_eq!(find_program(&tb, Kind::Obfs4), Some(exe.clone()));

        assert_eq!(find_program(&tb, Kind::Snowflake), Some(exe.clone()));
        let lines = builtin_bridges(&tb, Kind::Obfs4).unwrap();
        assert!(builtin_bridges(&tb, Kind::Snowflake).is_err());

        let data = temp("data");
        assert_eq!(current(&data), Current::Direct);

        assert!(save(&data, &lines, None).is_err());
        save(&data, &lines, Some(&exe)).unwrap();
        let o = crate::tor::TorOptions::load_files(&data).unwrap();
        assert_eq!(o.bridges, lines);
        assert_eq!(o.pt_path, Some(exe));
        assert_eq!(o.pt_protocols, vec!["obfs4".to_string()]);
        assert_eq!(
            current(&data),
            Current::Bridges {
                protocol: "obfs4".into(),
                count: 1
            }
        );
        clear(&data).unwrap();
        assert_eq!(current(&data), Current::Direct);
        let _ = std::fs::remove_dir_all(tb);
        let _ = std::fs::remove_dir_all(data);
    }
}

#[cfg(test)]
mod local {
    #[test]
    #[ignore]
    fn finds_the_installed_tor_browser() {
        let dir = super::find_tor_browser().expect("Tor Browser folder");
        for kind in [super::Kind::Obfs4, super::Kind::Snowflake] {
            let program = super::find_program(&dir, kind).expect("program");
            let lines = super::builtin_bridges(&dir, kind).expect("bridges");
            super::validate_lines(&lines).expect("valid lines");
            println!(
                "{}: {} bridges via {}",
                kind.name(),
                lines.len(),
                program.display()
            );
        }
    }
}
