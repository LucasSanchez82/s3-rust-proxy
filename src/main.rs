mod config;
mod crypto;
mod proxy;
mod s3_op;
mod signer;

use anyhow::{Context, Result};
use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::{Args, ProxyConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    info!(
        listen = %args.listen,
        upstream = %args.upstream,
        region = %args.region,
        "starting s3-proxy"
    );

    let cfg = ProxyConfig::from_args(&args).context("failed to initialize proxy config")?;

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let cfg = cfg.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let cfg = cfg.clone();
                async move { proxy::handle(req, cfg).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!(peer = %peer, error = %e, "connection closed with error");
            }
        });
    }
}
