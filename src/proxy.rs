use anyhow::Result;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::{self, ByteStream};
use crate::s3_op::S3Operation;
use crate::signer::sign_request;

/// Type de corps pour les réponses du proxy (streaming).
/// On utilise `UnsyncBoxBody` plutôt que `BoxBody` parce que le stream produit
/// par `async_stream::try_stream!` (utilisé côté déchiffrement) est `Send`
/// mais pas `Sync`. `UnsyncBoxBody` n'impose que `Send`, ce qui est suffisant
/// pour hyper.
pub type ProxyBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// Handler principal appelé par hyper pour chaque requête.
pub async fn handle(
    req: Request<Incoming>,
    cfg: Arc<ProxyConfig>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let start = Instant::now();

    let method = req.method();
    let uri = req.uri();
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let op = S3Operation::detect(method.as_str(), path, query);

    // On isole la logique dans une fonction qui peut renvoyer une erreur
    // pour simplifier la gestion d'erreurs et toujours répondre proprement.
    match forward(req, cfg, &op, start).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!(op = op.label(), error = %e, "proxy error");
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("proxy error: {}", e),
            ))
        }
    }
}

async fn forward(
    req: Request<Incoming>,
    cfg: Arc<ProxyConfig>,
    op: &S3Operation,
    start: Instant,
) -> Result<Response<ProxyBody>> {
    let method = req.method().clone();
    let uri = req.uri();
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let content_length = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    info!(
        op = op.label(),
        method = %method,
        path = %path,
        bucket = op.bucket().unwrap_or(""),
        key = op.key().unwrap_or(""),
        content_length = content_length.unwrap_or(0),
        "s3 request"
    );

    // Construction de l'URL upstream
    let upstream_url = format!(
        "{}{}{}",
        cfg.upstream.trim_end_matches('/'),
        path,
        if query.is_empty() {
            "".to_string()
        } else {
            format!("?{}", query)
        }
    );

    // Doit-on chiffrer ce payload avant de l'envoyer à l'upstream ?
    // On se limite à PutObject en V1 (multipart = une part par requête, chacune
    // avec son propre header — casse la reconstruction côté GET).
    let encrypt = cfg.encryption_key.is_some() && matches!(op, S3Operation::PutObject { .. });

    // Filtrage des headers à ne pas forwarder.
    // En particulier: on vire Authorization (client) et Host (client) car
    // le signer va les recalculer pour l'upstream.
    //
    // Si on chiffre, on retire le Content-Length client (taille du clair) pour
    // le remplacer plus bas par celui du chiffré. Garder un Content-Length
    // explicite est indispensable : AWS S3 rejette les PutObject sans
    // Content-Length avec `MissingContentLength`, et le body streamé via
    // reqwest partirait sinon en `Transfer-Encoding: chunked`.
    let mut upstream_headers = http::HeaderMap::new();
    for (name, value) in req.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if should_strip_client_header(&lower) {
            continue;
        }
        if encrypt && is_payload_integrity_header(&lower) {
            // Les checksums/MD5/Content-Length sont calculés par le client sur
            // le clair : ils ne correspondent plus au chiffré qu'on envoie.
            continue;
        }
        if let Ok(n) = http::HeaderName::try_from(name.as_str()) {
            if let Ok(v) = http::HeaderValue::from_bytes(value.as_bytes()) {
                upstream_headers.insert(n, v);
            }
        }
    }
    // Host doit être celui de l'upstream (obligatoire pour SigV4)
    upstream_headers.insert(
        http::header::HOST,
        http::HeaderValue::from_str(&cfg.upstream_host)?,
    );
    // Recalcule un Content-Length cohérent avec la taille du chiffré.
    // Doit être inséré AVANT `sign_request`, qui signe ce header.
    if encrypt {
        if let Some(plain_len) = content_length {
            let enc_len = crypto::encrypted_size(plain_len);
            upstream_headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from(enc_len),
            );
        } else {
            warn!(
                op = op.label(),
                "encrypting upload without client Content-Length: upstream will likely reject"
            );
        }
    }

    // Conversion du body hyper -> reqwest::Body en streaming.
    // On compte les bytes *en clair* vus côté client — le compteur est
    // placé avant le chiffrement pour refléter ce que l'utilisateur envoie.
    let bytes_seen = Arc::new(AtomicU64::new(0));
    let plain_stream = incoming_to_byte_stream(req.into_body(), Arc::clone(&bytes_seen));

    let upstream_stream: ByteStream = if encrypt {
        let key = cfg.encryption_key.as_ref().expect("guarded by `encrypt`");
        debug!(op = op.label(), "encrypting upload body");
        crypto::encrypt_stream(plain_stream, key)
    } else {
        plain_stream
    };
    let upstream_body = reqwest::Body::wrap_stream(upstream_stream);

    // Construction de la requête http::Request pour le signer
    let mut http_req_builder = http::Request::builder()
        .method(method.as_str())
        .uri(&upstream_url);
    for (name, value) in upstream_headers.iter() {
        http_req_builder = http_req_builder.header(name, value);
    }
    let mut http_req = http_req_builder.body(upstream_body)?;

    // Signature SigV4 : ajoute Authorization, X-Amz-Date, X-Amz-Content-Sha256
    sign_request(&mut http_req, &cfg.signer)?;

    let signed_headers_dump: Vec<String> = http_req
        .headers()
        .iter()
        .map(|(n, v)| {
            let name = n.as_str();
            let val = v.to_str().unwrap_or("<binary>");
            let shown = if name.eq_ignore_ascii_case("authorization") {
                val.chars().take(80).collect::<String>() + "..."
            } else {
                val.to_string()
            };
            format!("{}={}", name, shown)
        })
        .collect();
    debug!(
        url = %upstream_url,
        headers = ?signed_headers_dump,
        "signed upstream request"
    );

    // Envoi via reqwest. On convertit http::Request<reqwest::Body> en
    // reqwest::Request manuellement car reqwest ne consomme pas directement
    // un http::Request (il passe par son builder).
    let (parts, body) = http_req.into_parts();
    let mut req_builder = cfg.client.request(
        reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?,
        &upstream_url,
    );
    for (name, value) in parts.headers.iter() {
        req_builder = req_builder.header(name.as_str(), value.as_bytes());
    }
    let upstream_req = req_builder.body(body).build()?;

    let upstream_resp = cfg.client.execute(upstream_req).await?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_content_length = upstream_resp.content_length();

    info!(
        op = op.label(),
        status = status.as_u16(),
        resp_content_length = resp_content_length.unwrap_or(0),
        req_bytes_sent = bytes_seen.load(Ordering::Relaxed),
        elapsed_ms = start.elapsed().as_millis() as u64,
        "upstream response headers received"
    );

    // Si erreur upstream, on bufferise le body pour le logger (typiquement petit XML).
    // Ça casse le streaming pour ce cas, mais c'est uniquement en erreur.
    if status.is_client_error() || status.is_server_error() {
        let body_bytes = upstream_resp.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body_bytes);
        warn!(
            op = op.label(),
            status = status.as_u16(),
            body = %body_str,
            "upstream returned error"
        );
        let mut builder = Response::builder().status(hyper::StatusCode::from_u16(status.as_u16())?);
        for (name, value) in resp_headers.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if should_strip_upstream_header(&lower) || lower == "content-length" {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        let full = http_body_util::Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed_unsync();
        return Ok(builder.body(full)?);
    }

    // Doit-on déchiffrer le payload avant de le renvoyer au client ?
    let decrypt = cfg.encryption_key.is_some() && matches!(op, S3Operation::GetObject { .. });

    // Conversion de la réponse reqwest en réponse hyper, en streamant le body.
    // Pipeline : upstream -> (decrypt?) -> compteur -> Frame -> hyper body.
    let resp_bytes_seen = Arc::new(AtomicU64::new(0));
    let resp_bytes_clone = Arc::clone(&resp_bytes_seen);
    let op_label = op.label();

    let raw_resp_stream: ByteStream = Box::pin(
        upstream_resp
            .bytes_stream()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    let resp_stream: ByteStream = if decrypt {
        let key = cfg.encryption_key.as_ref().expect("guarded by `decrypt`");
        debug!(op = op_label, "decrypting response body");
        crypto::decrypt_stream(raw_resp_stream, key)
    } else {
        raw_resp_stream
    };

    let stream = resp_stream.map_ok(move |chunk| {
        resp_bytes_clone.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        Frame::data(chunk)
    });

    let body = StreamBody::new(stream).boxed_unsync();

    // Construction de la réponse pour le client.
    // On vire les headers hop-by-hop ; et si on a déchiffré, on vire aussi
    // Content-Length (la taille stockée est celle du ciphertext, pas du clair)
    // — le client verra du chunked, ce qui est parfaitement légal en HTTP/1.1.
    let mut builder = Response::builder().status(hyper::StatusCode::from_u16(status.as_u16())?);
    for (name, value) in resp_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if should_strip_upstream_header(&lower) {
            continue;
        }
        if decrypt && lower == "content-length" {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    // On log la taille réelle reçue à la fin de la réponse via un hook.
    // Pour l'instant, on log juste au début ; un vrai log "fin de stream"
    // nécessiterait de wrapper le body dans un body qui log à la fin.
    debug!(op = op_label, "response streaming to client");

    Ok(builder.body(body)?)
}

/// Headers reçus du client qu'on ne veut PAS recopier vers l'upstream.
/// Soit ils sont hop-by-hop, soit ils vont être recalculés par le signer.
fn should_strip_client_header(lower: &str) -> bool {
    matches!(
        lower,
        "host"
            | "authorization"
            | "x-amz-date"
            | "x-amz-content-sha256"
            | "x-amz-security-token"
            | "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

/// Headers de réponse upstream qu'on ne veut PAS retransmettre au client.
fn should_strip_upstream_header(lower: &str) -> bool {
    matches!(lower, "connection" | "transfer-encoding" | "keep-alive")
}

/// Headers d'intégrité de payload calculés par le client sur le clair.
/// Une fois le body chiffré, ils ne matchent plus et font rejeter la requête
/// par l'upstream (BadDigest, InvalidChecksum, MissingContentLength, etc.).
/// Le Content-Length est recalculé plus bas ; les checksums sont simplement
/// retirés (la garantie d'intégrité de bout-en-bout est fournie par le
/// tag Poly1305 de chaque chunk chiffré).
fn is_payload_integrity_header(lower: &str) -> bool {
    matches!(lower, "content-length" | "content-md5" | "x-amz-sdk-checksum-algorithm")
        || lower.starts_with("x-amz-checksum-")
}

/// Convertit un body hyper::Incoming en `ByteStream` (Stream<Item=io::Result<Bytes>>),
/// en comptant les octets vus au passage. C'est la forme canonique attendue par
/// `crypto::encrypt_stream`, et directement consommable par `reqwest::Body::wrap_stream`.
fn incoming_to_byte_stream(incoming: Incoming, bytes_seen: Arc<AtomicU64>) -> ByteStream {
    use http_body_util::BodyStream;

    let stream = BodyStream::new(incoming)
        .map_ok(move |frame| {
            // BodyStream produit des Frame<Bytes> ; on extrait seulement les frames
            // de type data (on ignore les trailers, rarissimes en HTTP/1 classique).
            if let Ok(data) = frame.into_data() {
                bytes_seen.fetch_add(data.len() as u64, Ordering::Relaxed);
                data
            } else {
                Bytes::new()
            }
        })
        .map_err(|e: hyper::Error| std::io::Error::new(std::io::ErrorKind::Other, e));

    Box::pin(stream)
}

fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = Bytes::from(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>ProxyError</Code><Message>{}</Message></Error>"#,
        msg
    ));
    let full = http_body_util::Full::new(body)
        .map_err(|never| match never {})
        .boxed_unsync();
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(full)
        .unwrap()
}
