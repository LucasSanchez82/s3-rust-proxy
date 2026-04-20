use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::EncryptionKey;
use crate::signer::SignerConfig;

#[derive(Parser, Debug, Clone)]
#[command(name = "s3-proxy", about = "Streaming S3 proxy with SigV4 re-signing")]
pub struct Args {
    /// Adresse d'écoute du proxy
    #[arg(long, short, env = "PROXY_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// URL complète de l'upstream S3 (avec schéma)
    /// Ex: https://s3.eu-central-003.backblazeb2.com
    #[arg(long, short, env = "S3_UPSTREAM")]
    pub upstream: String,

    /// Credentials B2/S3 pour re-signer les requêtes vers l'upstream
    #[arg(long, short, env = "S3_ACCESS_KEY")]
    pub access_key: String,

    #[arg(long, short, env = "S3_SECRET_KEY")]
    pub secret_key: String,

    /// Région à utiliser pour la signature SigV4.
    /// Pour B2, c'est généralement la partie après "s3." dans le host
    /// (ex: "eu-central-003" pour s3.eu-central-003.backblazeb2.com)
    #[arg(long, short, env = "S3_REGION", default_value = "us-east-1")]
    pub region: String,

    /// Timeout pour les requêtes vers l'upstream (en secondes)
    #[arg(
        long,
        short = 't',
        env = "UPSTREAM_TIMEOUT_SECS",
        default_value_t = 300
    )]
    pub upstream_timeout_secs: u64,

    /// Clé de chiffrement en hex (64 caractères = 32 bytes).
    /// Si fournie, active le chiffrement AEAD côté PutObject et le
    /// déchiffrement côté GetObject. Laisse-la vide pour passer en clair.
    #[arg(long, short, env = "PROXY_ENCRYPTION_KEY")]
    pub encryption_key: Option<String>,
}

/// Configuration runtime partagée entre toutes les requêtes.
pub struct ProxyConfig {
    pub upstream: String,
    pub upstream_host: String,
    pub client: Client,
    pub signer: SignerConfig,
    pub encryption_key: Option<EncryptionKey>,
}

impl ProxyConfig {
    pub fn from_args(args: &Args) -> Result<Arc<Self>> {
        // Validation de l'upstream
        let upstream =
            if !args.upstream.starts_with("http://") && !args.upstream.starts_with("https://") {
                format!("https://{}", args.upstream)
            } else {
                args.upstream.clone()
            };

        let url = url::Url::parse(&upstream)
            .with_context(|| format!("invalid upstream URL: {}", upstream))?;
        let upstream_host = url
            .host_str()
            .context("upstream URL has no host")?
            .to_string();

        // Le client HTTP réutilise les connexions et supporte le streaming
        // (reqwest::Body::wrap_stream permet de streamer sans bufferiser).
        let client = Client::builder()
            .pool_max_idle_per_host(16)
            .timeout(Duration::from_secs(args.upstream_timeout_secs))
            .build()
            .context("failed to build reqwest client")?;

        let signer = SignerConfig::new(
            args.access_key.clone(),
            args.secret_key.clone(),
            args.region.clone(),
        );

        let encryption_key = args
            .encryption_key
            .as_deref()
            .map(EncryptionKey::from_hex)
            .transpose()
            .context("invalid --encryption-key")?;

        Ok(Arc::new(Self {
            upstream,
            upstream_host,
            client,
            signer,
            encryption_key,
        }))
    }
}
