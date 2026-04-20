use anyhow::{Context, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::SystemTime;

/// Credentials + infos nécessaires pour signer une requête vers un backend S3.
#[derive(Clone)]
pub struct SignerConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    /// "s3" pour S3 et compatibles (B2, MinIO, Ceph, etc.)
    pub service: String,
}

impl SignerConfig {
    pub fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self {
            access_key,
            secret_key,
            region,
            service: "s3".to_string(),
        }
    }
}

/// Signe une requête HTTP avec SigV4 pour S3, en mode UNSIGNED-PAYLOAD.
///
/// UNSIGNED-PAYLOAD permet de streamer le body sans connaître son hash à l'avance.
/// C'est officiellement supporté par AWS S3 et compatible avec Backblaze B2 / MinIO.
/// TLS protège l'intégrité du body en transit, et la signature couvre toujours
/// méthode/URL/headers, donc la sécurité reste solide pour un contexte de cluster.
///
/// La requête est modifiée in-place : les headers `Authorization`, `X-Amz-Date`,
/// `X-Amz-Content-Sha256` et `Host` sont ajoutés/écrasés.
pub fn sign_request(req: &mut http::Request<reqwest::Body>, cfg: &SignerConfig) -> Result<()> {
    // Construction de l'identité (credentials)
    let credentials = Credentials::new(
        cfg.access_key.clone(),
        cfg.secret_key.clone(),
        None, // session token (pour STS)
        None, // expiration
        "s3-proxy-static",
    );
    let identity: Identity = credentials.into();

    // Pour S3, le header `x-amz-content-sha256` est obligatoire.
    // Par défaut SigningSettings ne l'ajoute pas (PayloadChecksumKind::NoHeader),
    // ce qui fait échouer la validation côté serveur S3/B2.
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&cfg.region)
        .name(&cfg.service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .context("failed to build SigningParams")?
        .into();

    // Extraction des éléments nécessaires pour SignableRequest
    let method = req.method().as_str();
    let uri = req.uri().to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let signable = SignableRequest::new(
        method,
        &uri,
        header_refs.into_iter(),
        SignableBody::UnsignedPayload,
    )
    .context("failed to build SignableRequest")?;

    let (instructions, _signature) = sign(signable, &params)
        .context("failed to compute signature")?
        .into_parts();

    // Les "signing instructions" nous disent quels headers ajouter à la requête.
    // apply_to_request_http1x fait ça pour nous sur un http::Request.
    instructions.apply_to_request_http1x(req);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_adds_expected_headers() {
        let cfg = SignerConfig::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            "us-east-1".to_string(),
        );
        let mut req = http::Request::builder()
            .method("GET")
            .uri("https://s3.amazonaws.com/mybucket")
            .header("host", "s3.amazonaws.com")
            .body(reqwest::Body::from(""))
            .unwrap();

        sign_request(&mut req, &cfg).expect("signing succeeded");

        assert!(req.headers().contains_key("authorization"));
        assert!(req.headers().contains_key("x-amz-date"));
        let auth = req
            .headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    }
}
