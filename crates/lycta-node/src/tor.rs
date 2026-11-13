use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{DataStream, KeystoreSelector, TorClient};
use futures::Stream;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncSecretKey, HsId, HsIdKeypair};
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService, StreamRequest};
use tor_llcrypto::pk::{curve25519, ed25519};

use lycta_core::wire::ONION_PORT;

pub type Client = Arc<TorClient<tor_rtcompat::PreferredRuntime>>;
pub type Incoming = std::pin::Pin<Box<dyn Stream<Item = StreamRequest> + Send>>;

#[derive(Debug, Default, Clone)]
pub struct TorOptions {
    pub bridges: Vec<String>,

    pub pt_path: Option<PathBuf>,

    pub pt_protocols: Vec<String>,
}

impl TorOptions {
    pub fn load_files(data_dir: &Path) -> std::io::Result<Self> {
        let lines = |name: &str| -> std::io::Result<Vec<String>> {
            let p = data_dir.join(name);
            if !p.exists() {
                return Ok(Vec::new());
            }
            Ok(std::fs::read_to_string(p)?
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect())
        };
        let bridges = lines("bridges.txt")?;
        let mut t = lines("transport.txt")?.into_iter();
        let pt_path = t.next().map(PathBuf::from);
        let mut pt_protocols: Vec<String> = t.collect();
        if pt_path.is_some() && pt_protocols.is_empty() {
            pt_protocols.push("obfs4".into());
        }
        Ok(Self {
            bridges,
            pt_path,
            pt_protocols,
        })
    }
}

pub fn offline_client(data_dir: &Path) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let b = TorClientConfigBuilder::from_directories(data_dir.join("s"), data_dir.join("c"));
    let config = b.build().context("Tor configuration")?;
    Ok(TorClient::builder()
        .config(config)
        .create_unbootstrapped()?)
}

pub async fn bootstrap(data_dir: &Path, opts: &TorOptions) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state_dir = data_dir.join("tor-state");
    let cache_dir = data_dir.join("tor-cache");

    let _ = std::fs::remove_dir_all(state_dir.join("hss"));
    let _ = std::fs::remove_dir_all(state_dir.join("keystore"));

    let mut b = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir);
    b.address_filter().allow_onion_addrs(true);

    b.storage()
        .keystore()
        .primary()
        .kind(tor_config::ExplicitOrAuto::Explicit(
            tor_keymgr::config::ArtiKeystoreKind::Ephemeral,
        ));

    b.vanguards().mode(tor_config::ExplicitOrAuto::Explicit(
        tor_guardmgr::VanguardMode::Full,
    ));

    for line in &opts.bridges {
        let br: BridgeConfigBuilder = line
            .parse()
            .map_err(|e| anyhow!("invalid bridge line: {e}"))?;
        b.bridges().bridges().push(br);
    }
    if let Some(path) = &opts.pt_path {
        let mut t = TransportConfigBuilder::default();
        let protos = opts
            .pt_protocols
            .iter()
            .map(|p| {
                p.parse()
                    .map_err(|e| anyhow!("invalid transport protocol {p}: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        t.protocols(protos)
            .path(CfgPath::new(path.to_string_lossy().into_owned()))
            .run_on_startup(true);
        b.bridges().transports().push(t);
    }

    let config = b.build().context("Tor configuration")?;
    let client = TorClient::create_bootstrapped(config)
        .await
        .context("Tor bootstrap")?;
    Ok(client)
}

pub fn launch_slot(
    client: &Client,
    slot_id: u32,
    seed: &[u8; 32],
    authorized_client: &[u8; 32],
) -> Result<(Arc<RunningOnionService>, [u8; 32], Incoming)> {
    let nickname: HsNickname = format!("lc{slot_id}")
        .parse()
        .map_err(|e| anyhow!("invalid onion service nickname: {e:?}"))?;
    let client_nick = HsClientNickname::from_str("contact")
        .map_err(|e| anyhow!("invalid client nickname: {e:?}"))?;
    let client_key = HsClientDescEncKey::from(curve25519::PublicKey::from(*authorized_client));

    let mut cfg = OnionServiceConfigBuilder::default();
    cfg.nickname(nickname).enable_pow(true);
    cfg.restricted_discovery().enabled(true);
    cfg.restricted_discovery()
        .static_keys()
        .access()
        .push((client_nick, client_key));
    let svc_config = cfg.build().context("onion service configuration")?;

    let kp = ed25519::Keypair::from_bytes(seed);
    let expanded = ed25519::ExpandedKeypair::from(&kp);
    let onion_key = expanded.public().to_bytes();
    let hsid_kp = HsIdKeypair::from(expanded);

    let (service, rend) = client
        .launch_onion_service_with_hsid(svc_config, hsid_kp)
        .context("onion service launch")?
        .ok_or_else(|| anyhow!("onion service disabled"))?;

    let streams: Incoming = Box::pin(handle_rend_requests(rend));
    Ok((service, onion_key, streams))
}

pub fn add_discovery_key(client: &Client, onion_key: &[u8; 32], secret: &[u8; 32]) -> Result<()> {
    let hsid = HsId::from(*onion_key);
    let _ = client.remove_service_discovery_key(KeystoreSelector::Primary, hsid);
    let sk = HsClientDescEncSecretKey::from(curve25519::StaticSecret::from(*secret));
    client
        .insert_service_discovery_key(KeystoreSelector::Primary, hsid, sk)
        .context("discovery key")?;
    Ok(())
}

pub async fn accept(req: StreamRequest) -> Result<DataStream> {
    Ok(req.accept(Connected::new_empty()).await?)
}

pub async fn connect(client: &Client, onion_key: &[u8; 32]) -> Result<DataStream> {
    let addr = lycta_core::identity::onion_address(onion_key);
    Ok(client.connect((addr.as_str(), ONION_PORT)).await?)
}
