//! Chiffrement streaming des objets envoyés vers / reçus de l'upstream S3.
//!
//! Construction **STREAM** (Rogaway & Bellare, 2015) au-dessus de
//! ChaCha20-Poly1305 :
//!
//! ```text
//! fichier chiffré = header || chunk_0 || chunk_1 || ... || chunk_n
//!   header  = magic(4) || version(1) || nonce_base(7)                  // 12 bytes en clair
//!   chunk_i = AEAD(nonce_i, plain_i) = ciphertext || tag(16)
//!   nonce_i = nonce_base(7) || counter(4, big-endian) || flag(1)
//!             flag = 0 pour les chunks intermédiaires, 1 pour le dernier
//! ```
//!
//! Propriétés :
//! - Streaming réel : chaque chunk est chiffré / déchiffré indépendamment,
//!   la RAM reste bornée par la taille d'un chunk (64 KiB).
//! - Unicité du nonce : le `nonce_base` est tiré au hasard pour chaque
//!   fichier, le compteur garantit l'unicité au sein d'un fichier.
//! - Détection de troncature : seul le dernier chunk porte `flag=1`.
//!   Un attaquant qui tronque le fichier ne peut pas re-flagger le nouveau
//!   dernier chunk sans la clé.
//! - Détection de modification : tout bit modifié casse le tag Poly1305.

use anyhow::{bail, Context, Result};
use async_stream::try_stream;
use bytes::{Bytes, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures_util::stream::{Stream, StreamExt};
use rand::RngCore;
use std::io;
use std::pin::Pin;

const MAGIC: &[u8; 4] = b"S3PX";
const VERSION: u8 = 1;
const NONCE_BASE_SIZE: usize = 7;
const HEADER_SIZE: usize = MAGIC.len() + 1 + NONCE_BASE_SIZE;

/// Taille d'un chunk en clair. 64 KiB = compromis classique (age, miscreant) :
/// overhead du tag (16 / 65536 ≈ 0.024 %), latence et RAM raisonnables.
pub const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const CIPHER_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Taille exacte du flux produit par `encrypt_stream` pour un clair de
/// `plain_len` octets. Permet au proxy de renseigner un `Content-Length`
/// upstream correct (AWS S3 refuse `Transfer-Encoding: chunked` sur PutObject).
///
/// Formule : `HEADER + plain_len + TAG * num_chunks`, où `num_chunks` vaut
/// 1 pour un clair vide (on émet tout de même un chunk final portant le tag),
/// sinon `ceil(plain_len / CHUNK_SIZE)`.
pub fn encrypted_size(plain_len: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    let num_chunks = if plain_len == 0 {
        1
    } else {
        plain_len / chunk + u64::from(plain_len % chunk != 0)
    };
    HEADER_SIZE as u64 + plain_len + TAG_SIZE as u64 * num_chunks
}

/// Type agnostique utilisé aux points de branchement dans `proxy.rs`.
pub type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

/// Clé symétrique (32 bytes pour ChaCha20-Poly1305).
#[derive(Clone)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Parse une clé en hex (64 caractères).
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).context("encryption key must be hex")?;
        if bytes.len() != 32 {
            bail!(
                "encryption key must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            );
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        Ok(Self(k))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }
}

fn make_nonce(base: &[u8; NONCE_BASE_SIZE], counter: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..NONCE_BASE_SIZE].copy_from_slice(base);
    nonce[NONCE_BASE_SIZE..NONCE_BASE_SIZE + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Chiffre un flux d'octets en clair en un flux chiffré (header + chunks).
pub fn encrypt_stream(mut input: ByteStream, key: &EncryptionKey) -> ByteStream {
    let cipher = key.cipher();
    Box::pin(try_stream! {
        // 1. Nonce de base aléatoire (7 bytes), émis en clair dans le header.
        let mut base = [0u8; NONCE_BASE_SIZE];
        rand::thread_rng().fill_bytes(&mut base);

        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&base);
        yield Bytes::from(header);

        // 2. Découpage en chunks de CHUNK_SIZE bytes en clair.
        //    On bufferise au minimum CHUNK_SIZE + 1 byte avant d'émettre
        //    un chunk non-final : ça garantit qu'on sait si le chunk courant
        //    est le dernier (indispensable pour fixer `flag_final`).
        let mut buffer = BytesMut::new();
        let mut counter: u32 = 0;

        loop {
            let mut have_more = true;
            while buffer.len() <= CHUNK_SIZE {
                match input.next().await {
                    Some(res) => buffer.extend_from_slice(&res?),
                    None => { have_more = false; break; }
                }
            }

            let final_flag = !have_more;
            let take = if have_more { CHUNK_SIZE } else { buffer.len() };
            let plain = buffer.split_to(take).freeze();

            let nonce = make_nonce(&base, counter, final_flag);
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
                .map_err(|_| io_err("encryption failed"))?;
            counter = counter
                .checked_add(1)
                .ok_or_else(|| io_err("too many chunks (counter overflow)"))?;
            yield Bytes::from(ct);

            if final_flag {
                break;
            }
        }
    })
}

/// Déchiffre un flux produit par `encrypt_stream`. Échoue si :
/// - le header est tronqué / magic ou version invalides,
/// - un byte du ciphertext a été modifié (tag Poly1305),
/// - le dernier chunk reçu n'avait pas le `flag_final` (troncature).
pub fn decrypt_stream(mut input: ByteStream, key: &EncryptionKey) -> ByteStream {
    let cipher = key.cipher();
    Box::pin(try_stream! {
        // 1. Lire et valider le header (12 bytes).
        let mut header_buf = BytesMut::with_capacity(HEADER_SIZE);
        while header_buf.len() < HEADER_SIZE {
            match input.next().await {
                Some(res) => header_buf.extend_from_slice(&res?),
                None => Err(io_err("unexpected EOF in encrypted header"))?,
            }
        }
        if &header_buf[..MAGIC.len()] != MAGIC {
            Err(io_err("bad magic: not an encrypted object"))?;
        }
        if header_buf[MAGIC.len()] != VERSION {
            Err(io_err(format!(
                "unsupported encryption format version: {}",
                header_buf[MAGIC.len()]
            )))?;
        }
        let mut base = [0u8; NONCE_BASE_SIZE];
        base.copy_from_slice(&header_buf[MAGIC.len() + 1..HEADER_SIZE]);

        // Garder le surplus au-delà du header : le premier chunk chiffré
        // est souvent déjà (au moins partiellement) arrivé dans le même Bytes.
        let mut buffer = BytesMut::new();
        if header_buf.len() > HEADER_SIZE {
            buffer.extend_from_slice(&header_buf[HEADER_SIZE..]);
        }

        // 2. Boucle de déchiffrement, même logique que l'émetteur :
        //    on attend d'avoir > CIPHER_CHUNK_SIZE bytes pour savoir si le
        //    chunk courant est le dernier.
        let mut counter: u32 = 0;
        loop {
            let mut have_more = true;
            while buffer.len() <= CIPHER_CHUNK_SIZE {
                match input.next().await {
                    Some(res) => buffer.extend_from_slice(&res?),
                    None => { have_more = false; break; }
                }
            }

            let final_flag = !have_more;
            let take = if have_more { CIPHER_CHUNK_SIZE } else { buffer.len() };

            // Chaque chunk chiffré doit au moins contenir le tag Poly1305.
            if final_flag && take < TAG_SIZE {
                Err(io_err("ciphertext truncated: missing final tag"))?;
            }

            let ct = buffer.split_to(take).freeze();
            let nonce = make_nonce(&base, counter, final_flag);
            let plain = cipher
                .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                .map_err(|_| io_err("decryption failed (tampering or wrong key)"))?;
            counter = counter
                .checked_add(1)
                .ok_or_else(|| io_err("too many chunks (counter overflow)"))?;
            yield Bytes::from(plain);

            if final_flag {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    fn key_from(fill: u8) -> EncryptionKey {
        EncryptionKey([fill; 32])
    }

    fn input_from(data: Vec<u8>, chunk: usize) -> ByteStream {
        let chunks: Vec<io::Result<Bytes>> = data
            .chunks(chunk.max(1))
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Box::pin(stream::iter(chunks))
    }

    async fn collect(mut s: ByteStream) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    async fn round_trip(plaintext: Vec<u8>, in_chunk: usize, mid_chunk: usize) {
        let key = key_from(0x42);
        let encrypted = collect(encrypt_stream(
            input_from(plaintext.clone(), in_chunk),
            &key,
        ))
        .await
        .expect("encrypt");

        assert!(encrypted.len() >= HEADER_SIZE + TAG_SIZE);
        assert_eq!(&encrypted[..MAGIC.len()], MAGIC);
        assert_eq!(
            encrypted.len() as u64,
            encrypted_size(plaintext.len() as u64),
            "encrypted_size() doit prédire la taille exacte du flux chiffré"
        );

        let decrypted = collect(decrypt_stream(input_from(encrypted, mid_chunk), &key))
            .await
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn round_trip_empty() {
        round_trip(vec![], 1024, 1024).await;
    }

    #[tokio::test]
    async fn round_trip_small() {
        round_trip((0..1000u16).map(|i| i as u8).collect(), 128, 333).await;
    }

    #[tokio::test]
    async fn round_trip_exact_chunk() {
        round_trip(vec![0xab; CHUNK_SIZE], 4096, 4096).await;
    }

    #[tokio::test]
    async fn round_trip_cross_boundary() {
        round_trip(vec![0x5a; CHUNK_SIZE + 1], 4096, 4096).await;
    }

    #[tokio::test]
    async fn round_trip_multi_chunks() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 3 + 123).map(|i| (i * 7) as u8).collect();
        round_trip(data, 9000, 2048).await;
    }

    #[tokio::test]
    async fn tampering_detected() {
        let key = key_from(3);
        let plaintext = vec![0u8; 50_000];
        let mut encrypted = collect(encrypt_stream(input_from(plaintext, 1024), &key))
            .await
            .unwrap();
        let idx = HEADER_SIZE + (encrypted.len() - HEADER_SIZE) / 2;
        encrypted[idx] ^= 0x01;
        let res = collect(decrypt_stream(input_from(encrypted, 4096), &key)).await;
        assert!(res.is_err(), "tampering should have been detected");
    }

    #[tokio::test]
    async fn truncation_detected() {
        let key = key_from(5);
        let plaintext = vec![0u8; CHUNK_SIZE * 3];
        let encrypted = collect(encrypt_stream(input_from(plaintext, 1024), &key))
            .await
            .unwrap();
        // Couper le dernier chunk complet (CHUNK_SIZE + TAG_SIZE bytes).
        let truncated = encrypted[..encrypted.len() - CIPHER_CHUNK_SIZE].to_vec();
        let res = collect(decrypt_stream(input_from(truncated, 4096), &key)).await;
        assert!(res.is_err(), "truncation should have been detected");
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let k1 = key_from(1);
        let k2 = key_from(2);
        let encrypted = collect(encrypt_stream(input_from(vec![42; 5000], 1024), &k1))
            .await
            .unwrap();
        let res = collect(decrypt_stream(input_from(encrypted, 1024), &k2)).await;
        assert!(res.is_err(), "wrong key should fail");
    }

    #[tokio::test]
    async fn bad_magic_fails() {
        let key = key_from(7);
        let junk = vec![0u8; 1000];
        let res = collect(decrypt_stream(input_from(junk, 1024), &key)).await;
        assert!(res.is_err());
    }

    #[test]
    fn key_hex_parsing() {
        let hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let key = EncryptionKey::from_hex(hex).expect("parse");
        assert_eq!(key.0, [0x01u8; 32]);

        assert!(EncryptionKey::from_hex("abcd").is_err());
        assert!(EncryptionKey::from_hex("zz").is_err());
    }
}
