use std::path::PathBuf;

use anyhow::Result;
use lycta_node::bridges;
use lycta_node::tor::{self, TorOptions};
use lycta_node::update;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("temp dir"));
    let url = args
        .next()
        .unwrap_or_else(|| "https://check.torproject.org/api/ip".into());
    std::fs::create_dir_all(&dir)?;
    match args.next().as_deref() {
        Some("obfs4") => {
            let n = bridges::use_tor_browser(&dir, bridges::Kind::Obfs4)?;
            println!("using {n} obfs4 bridges from Tor Browser");
        }
        Some("snowflake") => {
            let n = bridges::use_tor_browser(&dir, bridges::Kind::Snowflake)?;
            println!("using {n} snowflake bridges from Tor Browser");
        }
        _ => bridges::clear(&dir)?,
    }
    let client = tor::bootstrap(&dir, &TorOptions::load_files(&dir)?).await?;
    let body = update::https_get(&client, &url, 1024 * 1024).await?;
    println!("{} bytes", body.len());
    println!("{}", String::from_utf8_lossy(&body[..body.len().min(300)]));
    std::process::exit(0);
}
