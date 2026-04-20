use bytes::Bytes;

/// Inspecte un corps de requête pour produire un résumé loggable sans vider
/// la mémoire en cas de gros upload.
pub struct BodyInspection {
    pub size: usize,
    pub content_type_guess: &'static str,
    pub preview: String,
    pub sha256_prefix: String,
}

/// Taille max d'aperçu texte (en octets) — on reste modeste pour ne pas polluer les logs.
const PREVIEW_BYTES: usize = 256;

pub fn inspect(body: &Bytes, declared_content_type: Option<&str>) -> BodyInspection {
    let size = body.len();
    let content_type_guess = guess_content_type(body, declared_content_type);
    let preview = build_preview(body, content_type_guess);
    let sha256_prefix = sha256_prefix(body);

    BodyInspection {
        size,
        content_type_guess,
        preview,
        sha256_prefix,
    }
}

/// Devine le type de contenu à partir de la déclaration + de la signature (magic bytes).
/// La détection est volontairement basique, elle suffit pour distinguer les gros
/// cas qui reviennent tout le temps dans un proxy S3.
fn guess_content_type(body: &Bytes, declared: Option<&str>) -> &'static str {
    if body.is_empty() {
        return "empty";
    }

    // Magic bytes courants
    if body.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png";
    }
    if body.starts_with(b"\xff\xd8\xff") {
        return "image/jpeg";
    }
    if body.starts_with(b"GIF87a") || body.starts_with(b"GIF89a") {
        return "image/gif";
    }
    if body.starts_with(b"%PDF") {
        return "application/pdf";
    }
    if body.starts_with(b"PK\x03\x04") {
        // zip / docx / xlsx / jar...
        return "application/zip";
    }
    if body.starts_with(b"\x1f\x8b") {
        return "application/gzip";
    }

    // Si c'est de l'UTF-8 valide, on regarde la forme
    if let Ok(text) = std::str::from_utf8(body) {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return "application/json";
        }
        if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
            return "application/xml";
        }
        // Heuristique très grossière pour le CSV
        if trimmed.lines().take(3).all(|l| l.contains(',')) && !trimmed.is_empty() {
            return "text/csv";
        }
        return "text/plain";
    }

    // Si rien ne matche, on fait confiance au Content-Type déclaré si présent
    match declared {
        Some(ct) if ct.starts_with("image/") => "image/*",
        Some(ct) if ct.starts_with("video/") => "video/*",
        Some(ct) if ct.starts_with("audio/") => "audio/*",
        _ => "application/octet-stream",
    }
}

fn build_preview(body: &Bytes, content_type: &str) -> String {
    // Pour les types textuels on extrait un snippet UTF-8, sinon on fait un hexdump court.
    let is_text = matches!(
        content_type,
        "text/plain" | "text/csv" | "application/json" | "application/xml"
    );

    if is_text {
        if let Ok(s) = std::str::from_utf8(body) {
            let preview: String = s
                .chars()
                .take(PREVIEW_BYTES)
                .map(|c| {
                    if c.is_control() && c != '\n' && c != '\t' {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
            return preview.replace('\n', "\\n");
        }
    }

    // Hexdump des 32 premiers octets
    let take = body.len().min(32);
    let hex: String = body[..take]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    format!("hex: {}{}", hex, if body.len() > take { "..." } else { "" })
}

/// Un "hash-like" tout simple à base d'octets pour tracer les doublons dans les logs.
/// On n'a pas besoin d'un vrai SHA256 cryptographique ici (ce serait une dépendance en plus) ;
/// un FNV-1a 64 bits suffit largement pour de la corrélation.
fn sha256_prefix(body: &Bytes) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in body.iter() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_json() {
        let body = Bytes::from(r#"{"hello":"world"}"#);
        let i = inspect(&body, None);
        assert_eq!(i.content_type_guess, "application/json");
        assert!(i.preview.contains("hello"));
    }

    #[test]
    fn detects_png() {
        let body = Bytes::from_static(b"\x89PNG\r\n\x1a\nrest");
        let i = inspect(&body, None);
        assert_eq!(i.content_type_guess, "image/png");
    }

    #[test]
    fn handles_empty() {
        let body = Bytes::new();
        let i = inspect(&body, None);
        assert_eq!(i.size, 0);
        assert_eq!(i.content_type_guess, "empty");
    }
}
