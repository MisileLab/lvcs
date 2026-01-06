use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

use anyhow::Result;
use blake3::Hash;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::{DigitallySignedStruct, SignatureScheme};

use tokio::io::AsyncWriteExt;

use lvcs_core::{list_refs, read_ref, write_ref, Repo, RepoLock, Store};

const DOMAIN_AUTH2: &[u8] = b"lvcs:auth2\0";
const DOMAIN_AUTH3: &[u8] = b"lvcs:auth3\0";
const DOMAIN_SESSION: &[u8] = b"lvcs:session\0";

fn ensure_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    ensure_crypto_provider();
    let mut rustls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    rustls_config.alpn_protocols = vec![b"lvcs/1".to_vec()];
    let quic = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic));
    server_config.transport = Arc::new(quinn::TransportConfig::default());
    Ok(server_config)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone)]
pub struct KeyConfig {
    pub psk: [u8; 32],
    pub role: Role,
}

pub struct ServerConfigData {
    pub addr: SocketAddr,
    pub repos: HashMap<String, PathBuf>,
    pub keys: HashMap<String, KeyConfig>,
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

pub struct ClientConfigData {
    pub addr: SocketAddr,
    pub repo: String,
    pub key_id: String,
    pub psk: [u8; 32],
    pub known_hosts: PathBuf,
}

#[derive(Debug)]
struct TrustOnFirstUseVerifier;

impl ServerCertVerifier for TrustOnFirstUseVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub async fn run_server(config: ServerConfigData) -> Result<()> {
    ensure_crypto_provider();
    let cert = config.cert.clone();
    let key = config.key.clone_key();
    let config = Arc::new(config);
    let server_config = build_server_config(cert, key)?;
    let endpoint = Endpoint::server(server_config, config.addr)?;

    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("accept failed"))?;
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(incoming, config).await {
                eprintln!("connection error: {err}");
            }
        });
    }
}

async fn handle_connection(incoming: quinn::Incoming, config: Arc<ServerConfigData>) -> Result<()> {
    let connection = incoming.await?;
    let (mut send, mut recv) = connection.accept_bi().await?;

    let auth1 = read_message(&mut recv).await?;
    let (key_id, client_nonce) = match auth1 {
        Message::Auth1 {
            key_id,
            client_nonce,
        } => (key_id, client_nonce),
        _ => anyhow::bail!("expected auth1"),
    };

    let key = config
        .keys
        .get(&key_id)
        .ok_or_else(|| anyhow::anyhow!("unknown key"))?;
    let server_nonce = random_nonce();
    let auth2_mac = blake3::keyed_hash(
        &key.psk,
        &mac_input(DOMAIN_AUTH2, &client_nonce, &server_nonce),
    );
    write_message(
        &mut send,
        &Message::Auth2 {
            server_nonce,
            mac: *auth2_mac.as_bytes(),
        },
    )
    .await?;

    let auth3 = read_message(&mut recv).await?;
    let auth3_mac = match auth3 {
        Message::Auth3 { mac } => mac,
        _ => anyhow::bail!("expected auth3"),
    };
    let expected = blake3::keyed_hash(
        &key.psk,
        &mac_input(DOMAIN_AUTH3, &client_nonce, &server_nonce),
    );
    if auth3_mac != *expected.as_bytes() {
        anyhow::bail!("auth failed");
    }
    let _session = blake3::keyed_hash(
        &key.psk,
        &mac_input(DOMAIN_SESSION, &client_nonce, &server_nonce),
    );

    let hello = read_message(&mut recv).await?;
    let repo_name = match hello {
        Message::Hello { repo } => repo,
        _ => anyhow::bail!("expected hello"),
    };
    let repo_path = config
        .repos
        .get(&repo_name)
        .ok_or_else(|| anyhow::anyhow!("unknown repo"))?
        .clone();

    write_message(&mut send, &Message::HelloOk).await?;

    loop {
        let msg = match read_message(&mut recv).await {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match msg {
            Message::ListRefs => {
                let repo = Repo::open(&repo_path)?;
                let refs = list_refs(&repo)?
                    .into_iter()
                    .map(|(path, oid)| (path.to_string_lossy().to_string(), oid))
                    .collect();
                write_message(&mut send, &Message::ListRefsResp { refs }).await?;
            }
            Message::Fetch { wants: _ } => {
                let repo = Repo::open(&repo_path)?;
                let store = Store::new(repo.clone());
                let reachable = lvcs_core::reachable_objects(&repo, &store)?;
                let pack = lvcs_core::write_pack(
                    &repo,
                    &store,
                    &reachable.iter().copied().collect::<Vec<_>>(),
                )?;
                let pack_bytes = tokio::fs::read(&pack.pack_path).await?;
                let hash = blake3::hash(&pack_bytes[..pack_bytes.len().saturating_sub(32)]);
                write_message(
                    &mut send,
                    &Message::FetchResp {
                        pack_len: pack_bytes.len() as u64,
                        pack_hash: *hash.as_bytes(),
                    },
                )
                .await?;
                send.write_all(&pack_bytes).await?;
                send.flush().await?;
            }
            Message::Push {
                updates,
                pack_len,
                pack_hash,
                force,
            } => {
                if key.role != Role::ReadWrite {
                    write_message(
                        &mut send,
                        &Message::PushResp {
                            ok: false,
                            message: "permission denied".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
                let repo = Repo::open(&repo_path)?;
                let _lock = RepoLock::acquire(repo.repo_dir())?;
                let store = Store::new(repo.clone());
                let mut pack_bytes = vec![0u8; pack_len as usize];
                recv.read_exact(&mut pack_bytes).await?;
                let computed = blake3::hash(&pack_bytes[..pack_bytes.len().saturating_sub(32)]);
                if computed.as_bytes() != pack_hash.as_slice() {
                    write_message(
                        &mut send,
                        &Message::PushResp {
                            ok: false,
                            message: "pack hash mismatch".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
                let pack_path = repo.pack_dir().join("push.tmp.pack");
                tokio::fs::write(&pack_path, &pack_bytes).await?;
                lvcs_core::import_pack(&pack_path, &store)?;

                let verify = lvcs_core::fsck(&repo, &store)?;
                if !verify.issues.is_empty() {
                    write_message(
                        &mut send,
                        &Message::PushResp {
                            ok: false,
                            message: "fsck failed after import".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }

                for update in &updates {
                    let path = Path::new(&update.name);
                    let current = read_ref(&repo, path)?;
                    if let Some(new_oid) = update.new {
                        let _ = lvcs_core::reachable_from(&store, &[new_oid])?;
                    }
                    if !force {
                        if let Some(old) = update.old {
                            if current != Some(old) {
                                anyhow::bail!("non-fast-forward");
                            }
                            if let Some(new_oid) = update.new {
                                if !is_ancestor(&store, &old, &new_oid)? {
                                    anyhow::bail!("non-fast-forward");
                                }
                            }
                        }
                    }
                    match update.new {
                        Some(new_oid) => write_ref(&repo, path, &new_oid)?,
                        None => {
                            let full = repo.repo_dir().join(path);
                            if full.exists() {
                                tokio::fs::remove_file(full).await?;
                            }
                        }
                    }
                    append_reflog(&repo, &key_id, update, force)?;
                }

                write_message(
                    &mut send,
                    &Message::PushResp {
                        ok: true,
                        message: "ok".to_string(),
                    },
                )
                .await?;
            }
            _ => {
                write_message(
                    &mut send,
                    &Message::Error {
                        message: "unexpected message".to_string(),
                    },
                )
                .await?;
            }
        }
    }

    Ok(())
}

pub async fn connect_client(config: ClientConfigData) -> Result<Client> {
    ensure_crypto_provider();
    let verifier = Arc::new(TrustOnFirstUseVerifier);
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"lvcs/1".to_vec()];
    let client_crypto = QuicClientConfig::try_from(client_crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(client_crypto));
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint.connect(config.addr, "lvcs")?.await?;

    let fingerprint = peer_fingerprint(&connection)?;
    check_known_host(&config.known_hosts, &config.addr.to_string(), &fingerprint)?;

    let (mut send, mut recv) = connection.open_bi().await?;

    let client_nonce = random_nonce();
    write_message(
        &mut send,
        &Message::Auth1 {
            key_id: config.key_id.clone(),
            client_nonce,
        },
    )
    .await?;

    let auth2 = read_message(&mut recv).await?;
    let (server_nonce, mac) = match auth2 {
        Message::Auth2 { server_nonce, mac } => (server_nonce, mac),
        _ => anyhow::bail!("expected auth2"),
    };
    let expected = blake3::keyed_hash(
        &config.psk,
        &mac_input(DOMAIN_AUTH2, &client_nonce, &server_nonce),
    );
    if mac != *expected.as_bytes() {
        anyhow::bail!("auth2 mac mismatch");
    }

    let auth3 = blake3::keyed_hash(
        &config.psk,
        &mac_input(DOMAIN_AUTH3, &client_nonce, &server_nonce),
    );
    write_message(
        &mut send,
        &Message::Auth3 {
            mac: *auth3.as_bytes(),
        },
    )
    .await?;

    write_message(
        &mut send,
        &Message::Hello {
            repo: config.repo.clone(),
        },
    )
    .await?;
    let hello = read_message(&mut recv).await?;
    match hello {
        Message::HelloOk => {}
        Message::Error { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected hello response"),
    }

    Ok(Client {
        send,
        recv,
        _endpoint: endpoint,
    })
}

pub struct Client {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _endpoint: Endpoint,
}

impl Client {
    pub async fn list_refs(&mut self) -> Result<Vec<(String, lvcs_core::Oid)>> {
        write_message(&mut self.send, &Message::ListRefs).await?;
        match read_message(&mut self.recv).await? {
            Message::ListRefsResp { refs } => Ok(refs),
            Message::Error { message } => anyhow::bail!(message),
            _ => anyhow::bail!("unexpected list refs response"),
        }
    }

    pub async fn fetch_into(&mut self, repo: &Repo) -> Result<()> {
        write_message(&mut self.send, &Message::Fetch { wants: Vec::new() }).await?;
        let resp = read_message(&mut self.recv).await?;
        let (pack_len, pack_hash) = match resp {
            Message::FetchResp {
                pack_len,
                pack_hash,
            } => (pack_len, pack_hash),
            Message::Error { message } => anyhow::bail!(message),
            _ => anyhow::bail!("unexpected fetch response"),
        };
        let mut pack_bytes = vec![0u8; pack_len as usize];
        self.recv.read_exact(&mut pack_bytes).await?;
        let computed = blake3::hash(&pack_bytes[..pack_bytes.len().saturating_sub(32)]);
        if computed.as_bytes() != pack_hash.as_slice() {
            anyhow::bail!("pack hash mismatch");
        }
        let pack_path = repo.pack_dir().join("fetch.tmp.pack");
        tokio::fs::write(&pack_path, &pack_bytes).await?;
        let store = Store::new(repo.clone());
        lvcs_core::import_pack(&pack_path, &store)?;
        Ok(())
    }

    pub async fn push_from(
        &mut self,
        repo: &Repo,
        updates: Vec<RefUpdate>,
        force: bool,
    ) -> Result<()> {
        let store = Store::new(repo.clone());
        let reachable = lvcs_core::reachable_objects(repo, &store)?;
        let pack =
            lvcs_core::write_pack(repo, &store, &reachable.iter().copied().collect::<Vec<_>>())?;
        let pack_bytes = tokio::fs::read(&pack.pack_path).await?;
        let hash = blake3::hash(&pack_bytes[..pack_bytes.len().saturating_sub(32)]);
        write_message(
            &mut self.send,
            &Message::Push {
                updates: updates.clone(),
                pack_len: pack_bytes.len() as u64,
                pack_hash: *hash.as_bytes(),
                force,
            },
        )
        .await?;
        self.send.write_all(&pack_bytes).await?;
        self.send.flush().await?;
        match read_message(&mut self.recv).await? {
            Message::PushResp { ok, message } => {
                if ok {
                    Ok(())
                } else {
                    anyhow::bail!(message)
                }
            }
            Message::Error { message } => anyhow::bail!(message),
            _ => anyhow::bail!("unexpected push response"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RefUpdate {
    pub name: String,
    pub old: Option<lvcs_core::Oid>,
    pub new: Option<lvcs_core::Oid>,
}

#[derive(Clone, Debug)]
enum Message {
    Auth1 {
        key_id: String,
        client_nonce: [u8; 32],
    },
    Auth2 {
        server_nonce: [u8; 32],
        mac: [u8; 32],
    },
    Auth3 {
        mac: [u8; 32],
    },
    Hello {
        repo: String,
    },
    HelloOk,
    Error {
        message: String,
    },
    ListRefs,
    ListRefsResp {
        refs: Vec<(String, lvcs_core::Oid)>,
    },
    Fetch {
        wants: Vec<lvcs_core::Oid>,
    },
    FetchResp {
        pack_len: u64,
        pack_hash: [u8; 32],
    },
    Push {
        updates: Vec<RefUpdate>,
        pack_len: u64,
        pack_hash: [u8; 32],
        force: bool,
    },
    PushResp {
        ok: bool,
        message: String,
    },
}

async fn write_message(stream: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let mut payload = Vec::new();
    match msg {
        Message::Auth1 {
            key_id,
            client_nonce,
        } => {
            payload.push(1);
            write_string(&mut payload, key_id);
            payload.extend_from_slice(client_nonce);
        }
        Message::Auth2 { server_nonce, mac } => {
            payload.push(2);
            payload.extend_from_slice(server_nonce);
            payload.extend_from_slice(mac);
        }
        Message::Auth3 { mac } => {
            payload.push(3);
            payload.extend_from_slice(mac);
        }
        Message::Hello { repo } => {
            payload.push(4);
            write_string(&mut payload, repo);
        }
        Message::HelloOk => {
            payload.push(5);
        }
        Message::Error { message } => {
            payload.push(6);
            write_string(&mut payload, message);
        }
        Message::ListRefs => {
            payload.push(7);
        }
        Message::ListRefsResp { refs } => {
            payload.push(8);
            write_u32(&mut payload, refs.len() as u32);
            for (name, oid) in refs {
                write_string(&mut payload, name);
                payload.extend_from_slice(oid.as_bytes());
            }
        }
        Message::Fetch { wants } => {
            payload.push(9);
            write_u32(&mut payload, wants.len() as u32);
            for oid in wants {
                payload.extend_from_slice(oid.as_bytes());
            }
        }
        Message::FetchResp {
            pack_len,
            pack_hash,
        } => {
            payload.push(10);
            write_u64(&mut payload, *pack_len);
            payload.extend_from_slice(pack_hash);
        }
        Message::Push {
            updates,
            pack_len,
            pack_hash,
            force,
        } => {
            payload.push(11);
            payload.push(if *force { 1 } else { 0 });
            write_u32(&mut payload, updates.len() as u32);
            for update in updates {
                write_string(&mut payload, &update.name);
                write_oid_opt(&mut payload, update.old.as_ref());
                write_oid_opt(&mut payload, update.new.as_ref());
            }
            write_u64(&mut payload, *pack_len);
            payload.extend_from_slice(pack_hash);
        }
        Message::PushResp { ok, message } => {
            payload.push(12);
            payload.push(if *ok { 1 } else { 0 });
            write_string(&mut payload, message);
        }
    }

    let mut len = Vec::new();
    write_u32(&mut len, payload.len() as u32);
    stream.write_all(&len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message(stream: &mut quinn::RecvStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let mut cursor = Cursor::new(buf);
    let kind = read_u8(&mut cursor)?;
    let msg = match kind {
        1 => {
            let key_id = read_string(&mut cursor)?;
            let mut nonce = [0u8; 32];
            cursor.read_exact(&mut nonce)?;
            Message::Auth1 {
                key_id,
                client_nonce: nonce,
            }
        }
        2 => {
            let mut nonce = [0u8; 32];
            cursor.read_exact(&mut nonce)?;
            let mut mac = [0u8; 32];
            cursor.read_exact(&mut mac)?;
            Message::Auth2 {
                server_nonce: nonce,
                mac,
            }
        }
        3 => {
            let mut mac = [0u8; 32];
            cursor.read_exact(&mut mac)?;
            Message::Auth3 { mac }
        }
        4 => {
            let repo = read_string(&mut cursor)?;
            Message::Hello { repo }
        }
        5 => Message::HelloOk,
        6 => {
            let message = read_string(&mut cursor)?;
            Message::Error { message }
        }
        7 => Message::ListRefs,
        8 => {
            let count = read_u32(&mut cursor)? as usize;
            let mut refs = Vec::with_capacity(count);
            for _ in 0..count {
                let name = read_string(&mut cursor)?;
                let mut oid = [0u8; 32];
                cursor.read_exact(&mut oid)?;
                refs.push((name, lvcs_core::Oid::new(oid)));
            }
            Message::ListRefsResp { refs }
        }
        9 => {
            let count = read_u32(&mut cursor)? as usize;
            let mut wants = Vec::with_capacity(count);
            for _ in 0..count {
                let mut oid = [0u8; 32];
                cursor.read_exact(&mut oid)?;
                wants.push(lvcs_core::Oid::new(oid));
            }
            Message::Fetch { wants }
        }
        10 => {
            let pack_len = read_u64(&mut cursor)?;
            let mut hash = [0u8; 32];
            cursor.read_exact(&mut hash)?;
            Message::FetchResp {
                pack_len,
                pack_hash: hash,
            }
        }
        11 => {
            let force = read_u8(&mut cursor)? == 1;
            let count = read_u32(&mut cursor)? as usize;
            let mut updates = Vec::with_capacity(count);
            for _ in 0..count {
                let name = read_string(&mut cursor)?;
                let old = read_oid_opt(&mut cursor)?;
                let new = read_oid_opt(&mut cursor)?;
                updates.push(RefUpdate { name, old, new });
            }
            let pack_len = read_u64(&mut cursor)?;
            let mut hash = [0u8; 32];
            cursor.read_exact(&mut hash)?;
            Message::Push {
                updates,
                pack_len,
                pack_hash: hash,
                force,
            }
        }
        12 => {
            let ok = read_u8(&mut cursor)? == 1;
            let message = read_string(&mut cursor)?;
            Message::PushResp { ok, message }
        }
        _ => anyhow::bail!("unknown message"),
    };
    Ok(msg)
}

struct Cursor {
    buf: Vec<u8>,
    pos: usize,
}

impl Cursor {
    fn new(buf: Vec<u8>) -> Self {
        Self { buf, pos: 0 }
    }
}

impl std::io::Read for Cursor {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let to_read = remaining.min(out.len());
        if to_read == 0 {
            return Ok(0);
        }
        out[..to_read].copy_from_slice(&self.buf[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    write_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

fn write_oid_opt(buf: &mut Vec<u8>, oid: Option<&lvcs_core::Oid>) {
    match oid {
        Some(oid) => {
            buf.push(1);
            buf.extend_from_slice(oid.as_bytes());
        }
        None => buf.push(0),
    }
}

fn read_u8(cursor: &mut Cursor) -> Result<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32(cursor: &mut Cursor) -> Result<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(cursor: &mut Cursor) -> Result<u64> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn read_string(cursor: &mut Cursor) -> Result<String> {
    let len = read_u32(cursor)? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

fn read_oid_opt(cursor: &mut Cursor) -> Result<Option<lvcs_core::Oid>> {
    let flag = read_u8(cursor)?;
    if flag == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; 32];
    cursor.read_exact(&mut buf)?;
    Ok(Some(lvcs_core::Oid::new(buf)))
}

fn mac_input(domain: &[u8], client: &[u8; 32], server: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(domain);
    out.extend_from_slice(client);
    out.extend_from_slice(server);
    out
}

fn random_nonce() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let hash = blake3::hash(&now.to_be_bytes());
    bytes.copy_from_slice(hash.as_bytes());
    bytes
}

fn peer_fingerprint(connection: &quinn::Connection) -> Result<Hash> {
    let identity = connection
        .peer_identity()
        .ok_or_else(|| anyhow::anyhow!("missing peer identity"))?;
    let certs = identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .ok_or_else(|| anyhow::anyhow!("unexpected identity type"))?;
    let cert = certs.first().ok_or_else(|| anyhow::anyhow!("no cert"))?;
    Ok(blake3::hash(cert.as_ref()))
}

fn check_known_host(path: &Path, host: &str, fingerprint: &Hash) -> Result<()> {
    let mut entries = HashMap::new();
    if path.exists() {
        let contents = std::fs::read_to_string(path)?;
        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(host), Some(fp)) = (parts.next(), parts.next()) {
                entries.insert(host.to_string(), fp.to_string());
            }
        }
    }
    let fp_hex = fingerprint.to_hex().to_string();
    match entries.get(host) {
        Some(existing) => {
            if existing != &fp_hex {
                anyhow::bail!("server fingerprint mismatch");
            }
        }
        None => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut contents = entries
                .into_iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>();
            contents.push(format!("{host} {fp_hex}"));
            std::fs::write(path, contents.join("\n"))?;
        }
    }
    Ok(())
}

fn append_reflog(repo: &Repo, key_id: &str, update: &RefUpdate, force: bool) -> Result<()> {
    let path = repo.repo_dir().join("reflog");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let old = update
        .old
        .map(|oid| oid.to_hex())
        .unwrap_or_else(|| "0".repeat(64));
    let new = update
        .new
        .map(|oid| oid.to_hex())
        .unwrap_or_else(|| "0".repeat(64));
    let line = format!(
        "{ts} {key_id} {} {old} {new} {}\n",
        update.name,
        if force { 1 } else { 0 }
    );
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn is_ancestor(store: &Store, ancestor: &lvcs_core::Oid, tip: &lvcs_core::Oid) -> Result<bool> {
    let mut queue = vec![*tip];
    let mut seen = HashMap::new();
    while let Some(oid) = queue.pop() {
        if oid == *ancestor {
            return Ok(true);
        }
        if seen.insert(oid, ()).is_some() {
            continue;
        }
        let commit = lvcs_core::load_commit(store, &oid)?;
        for parent in commit.parents {
            queue.push(parent);
        }
    }
    Ok(false)
}

pub fn generate_self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["lvcs".to_string()])?;

    let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let cert = CertificateDer::from(cert);
    Ok((cert, PrivateKeyDer::from(key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use lvcs_core::commit_worktree;

    async fn spawn_server(
        config: ServerConfigData,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let cert = config.cert.clone();
        let key = config.key.clone_key();
        let config = Arc::new(config);
        let server_config = build_server_config(cert, key)?;
        let endpoint = Endpoint::server(server_config, config.addr)?;
        let addr = endpoint.local_addr()?;
        let config = Arc::clone(&config);
        let handle = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let _ = handle_connection(incoming, config).await;
            }
        });
        Ok((addr, handle))
    }

    #[tokio::test]
    async fn push_and_fetch_roundtrip() -> Result<()> {
        let temp = tempfile::tempdir().expect("tempdir");
        let server_repo = lvcs_core::Repo::init(temp.path().join("server")).expect("init");
        let client_repo = lvcs_core::Repo::init(temp.path().join("client")).expect("init");
        std::fs::write(client_repo.worktree().join("file.txt"), b"data").expect("write");

        let store = Store::new(client_repo.clone());
        let commit = commit_worktree(
            &client_repo,
            &store,
            "tester".to_string(),
            1,
            "msg".to_string(),
        )
        .expect("commit");

        let (cert, key) = generate_self_signed()?;
        let mut repos = HashMap::new();
        repos.insert("origin".to_string(), server_repo.worktree().to_path_buf());
        let mut keys = HashMap::new();
        let psk = [7u8; 32];
        keys.insert(
            "key1".to_string(),
            KeyConfig {
                psk,
                role: Role::ReadWrite,
            },
        );
        let (addr, _handle) = spawn_server(ServerConfigData {
            addr: "127.0.0.1:0".parse().expect("addr"),
            repos,
            keys,
            cert,
            key,
        })
        .await?;

        let known_hosts = temp.path().join("known_hosts");
        let mut client = connect_client(ClientConfigData {
            addr,
            repo: "origin".to_string(),
            key_id: "key1".to_string(),
            psk,
            known_hosts,
        })
        .await?;

        let update = RefUpdate {
            name: "refs/heads/main".to_string(),
            old: None,
            new: Some(commit.oid),
        };
        client.push_from(&client_repo, vec![update], false).await?;

        let fetch_repo = lvcs_core::Repo::init(temp.path().join("fetch")).expect("init");
        client.fetch_into(&fetch_repo).await?;
        let fetch_store = Store::new(fetch_repo.clone());
        let (_kind, data) = fetch_store.read_object(&commit.oid)?;
        match data {
            lvcs_core::ObjectData::Commit(_) => Ok(()),
            _ => Err(anyhow::anyhow!("missing commit")),
        }
    }
}
