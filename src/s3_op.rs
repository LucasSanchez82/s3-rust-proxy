use serde::Serialize;

/// Représente une opération S3 identifiée à partir de la requête HTTP.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum S3Operation {
    ListBuckets,
    ListObjects {
        bucket: String,
    },
    HeadBucket {
        bucket: String,
    },
    PutObject {
        bucket: String,
        key: String,
    },
    GetObject {
        bucket: String,
        key: String,
    },
    HeadObject {
        bucket: String,
        key: String,
    },
    DeleteObject {
        bucket: String,
        key: String,
    },
    CreateBucket {
        bucket: String,
    },
    DeleteBucket {
        bucket: String,
    },
    MultipartInit {
        bucket: String,
        key: String,
    },
    MultipartUpload {
        bucket: String,
        key: String,
        part: String,
    },
    MultipartComplete {
        bucket: String,
        key: String,
    },
    MultipartAbort {
        bucket: String,
        key: String,
    },
    Unknown,
}

impl S3Operation {
    /// Détecte l'opération S3 à partir de la méthode HTTP, du chemin et de la query string.
    /// On suit le style path-style (host/bucket/key).
    pub fn detect(method: &str, path: &str, query: &str) -> Self {
        let trimmed = path.trim_start_matches('/');

        if trimmed.is_empty() {
            return match method {
                "GET" => S3Operation::ListBuckets,
                _ => S3Operation::Unknown,
            };
        }

        let (bucket, key) = match trimmed.split_once('/') {
            Some((b, k)) if !k.is_empty() => (b.to_string(), Some(k.to_string())),
            _ => (trimmed.trim_end_matches('/').to_string(), None),
        };

        let has_uploads_param = query
            .split('&')
            .any(|p| p == "uploads" || p.starts_with("uploads="));
        let upload_id = query
            .split('&')
            .find_map(|p| p.strip_prefix("uploadId="))
            .map(|s| s.to_string());
        let part_number = query
            .split('&')
            .find_map(|p| p.strip_prefix("partNumber="))
            .map(|s| s.to_string());

        match (method, key) {
            ("GET", None) => S3Operation::ListObjects { bucket },
            ("HEAD", None) => S3Operation::HeadBucket { bucket },
            ("PUT", None) => S3Operation::CreateBucket { bucket },
            ("DELETE", None) => S3Operation::DeleteBucket { bucket },

            ("POST", Some(k)) if has_uploads_param => S3Operation::MultipartInit { bucket, key: k },
            ("POST", Some(k)) if upload_id.is_some() => {
                S3Operation::MultipartComplete { bucket, key: k }
            }
            ("PUT", Some(k)) if part_number.is_some() => S3Operation::MultipartUpload {
                bucket,
                key: k,
                part: part_number.unwrap_or_default(),
            },
            ("DELETE", Some(k)) if upload_id.is_some() => {
                S3Operation::MultipartAbort { bucket, key: k }
            }
            ("PUT", Some(k)) => S3Operation::PutObject { bucket, key: k },
            ("GET", Some(k)) => S3Operation::GetObject { bucket, key: k },
            ("HEAD", Some(k)) => S3Operation::HeadObject { bucket, key: k },
            ("DELETE", Some(k)) => S3Operation::DeleteObject { bucket, key: k },

            _ => S3Operation::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            S3Operation::ListBuckets => "ListBuckets",
            S3Operation::ListObjects { .. } => "ListObjects",
            S3Operation::HeadBucket { .. } => "HeadBucket",
            S3Operation::PutObject { .. } => "PutObject",
            S3Operation::GetObject { .. } => "GetObject",
            S3Operation::HeadObject { .. } => "HeadObject",
            S3Operation::DeleteObject { .. } => "DeleteObject",
            S3Operation::CreateBucket { .. } => "CreateBucket",
            S3Operation::DeleteBucket { .. } => "DeleteBucket",
            S3Operation::MultipartInit { .. } => "CreateMultipartUpload",
            S3Operation::MultipartUpload { .. } => "UploadPart",
            S3Operation::MultipartComplete { .. } => "CompleteMultipartUpload",
            S3Operation::MultipartAbort { .. } => "AbortMultipartUpload",
            S3Operation::Unknown => "Unknown",
        }
    }

    pub fn bucket(&self) -> Option<&str> {
        match self {
            S3Operation::ListObjects { bucket }
            | S3Operation::HeadBucket { bucket }
            | S3Operation::CreateBucket { bucket }
            | S3Operation::DeleteBucket { bucket }
            | S3Operation::PutObject { bucket, .. }
            | S3Operation::GetObject { bucket, .. }
            | S3Operation::HeadObject { bucket, .. }
            | S3Operation::DeleteObject { bucket, .. }
            | S3Operation::MultipartInit { bucket, .. }
            | S3Operation::MultipartUpload { bucket, .. }
            | S3Operation::MultipartComplete { bucket, .. }
            | S3Operation::MultipartAbort { bucket, .. } => Some(bucket),
            _ => None,
        }
    }

    pub fn key(&self) -> Option<&str> {
        match self {
            S3Operation::PutObject { key, .. }
            | S3Operation::GetObject { key, .. }
            | S3Operation::HeadObject { key, .. }
            | S3Operation::DeleteObject { key, .. }
            | S3Operation::MultipartInit { key, .. }
            | S3Operation::MultipartUpload { key, .. }
            | S3Operation::MultipartComplete { key, .. }
            | S3Operation::MultipartAbort { key, .. } => Some(key),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_list_buckets() {
        assert_eq!(
            S3Operation::detect("GET", "/", ""),
            S3Operation::ListBuckets
        );
    }

    #[test]
    fn detect_put_object() {
        let op = S3Operation::detect("PUT", "/mybucket/path/to/file.txt", "");
        assert_eq!(
            op,
            S3Operation::PutObject {
                bucket: "mybucket".into(),
                key: "path/to/file.txt".into(),
            }
        );
    }

    #[test]
    fn detect_multipart_upload_part() {
        let op = S3Operation::detect("PUT", "/b/k", "partNumber=3&uploadId=abc");
        assert_eq!(
            op,
            S3Operation::MultipartUpload {
                bucket: "b".into(),
                key: "k".into(),
                part: "3".into(),
            }
        );
    }
}
