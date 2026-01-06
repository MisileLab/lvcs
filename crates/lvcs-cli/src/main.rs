use std::collections::HashMap;
use std::env;
use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use lvcs_core::{
    commit_worktree, fsck, gc, list_tree, load_commit, merge, resolve_rev, walk_commits,
    CommitResult, Head, MergeOutcome, Repo, RepoLock, Store,
};
use lvcs_net::{
    connect_client, generate_self_signed, ClientConfigData, KeyConfig, RefUpdate, Role,
    ServerConfigData,
};

#[derive(Parser)]
#[command(name = "lvcs", version, about = "Lambda VCS")]
struct Cli {
    #[arg(long, default_value = "auto", global = true)]
    color: ColorMode,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        path: Option<PathBuf>,
    },
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(long)]
        author: Option<String>,
    },
    Log {
        #[arg(short, long)]
        count: Option<usize>,
        rev: Option<String>,
    },
    Tree {
        rev: Option<String>,
        #[arg(long)]
        long: bool,
        #[arg(long)]
        hash: bool,
        #[arg(long)]
        size: bool,
    },
    Checkout {
        rev: String,
        #[arg(long)]
        force: bool,
    },
    Merge {
        rev: String,
    },
    Gc,
    Fsck,
    Serve {
        #[arg(long, default_value = "0.0.0.0:7447")]
        addr: String,
        #[arg(long = "repo")]
        repos: Vec<String>,
        #[arg(long = "key")]
        keys: Vec<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Fetch {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        psk: String,
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    Push {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        psk: String,
        #[arg(long, default_value = "refs/heads/main")]
        refname: String,
        #[arg(long)]
        force: bool,
    },
    ListRefs {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        psk: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let use_color = color_enabled(&cli.color);

    match cli.command {
        Commands::Init { path } => {
            let target = path.unwrap_or_else(|| PathBuf::from("."));
            lvcs_core::init_repo(target)?;
        }
        Commands::Commit { message, author } => {
            let repo = Repo::open(".")?;
            let _lock = RepoLock::acquire(repo.repo_dir())?;
            let store = Store::new(repo.clone());
            let author = author.unwrap_or_else(default_author);
            let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
            let result = commit_worktree(&repo, &store, author, timestamp, message)?;
            print_commit_result(&result, use_color);
        }
        Commands::Log { count, rev } => {
            let repo = Repo::open(".")?;
            let store = Store::new(repo.clone());
            let oid = resolve_rev(&repo, rev.as_deref())?;
            let refs = lvcs_core::list_refs(&repo)?;
            let decorations = build_decorations(&repo, refs)?;
            let entries = walk_commits(&store, &oid, count.unwrap_or(10))?;
            for entry in entries {
                let decoration = decorations
                    .get(&entry.oid)
                    .map(|v| v.join(", "))
                    .unwrap_or_default();
                print_log_entry(
                    &entry.oid.to_hex(),
                    &entry.commit.message,
                    &decoration,
                    use_color,
                );
            }
        }
        Commands::Tree {
            rev,
            long,
            hash,
            size,
        } => {
            let repo = Repo::open(".")?;
            let store = Store::new(repo.clone());
            let oid = resolve_rev(&repo, rev.as_deref())?;
            let commit = load_commit(&store, &oid)?;
            let items = list_tree(&store, &commit.root)?;
            for item in items {
                print_tree_item(&item, long, hash, size, use_color);
            }
        }
        Commands::Checkout { rev, force } => {
            let repo = Repo::open(".")?;
            let _lock = RepoLock::acquire(repo.repo_dir())?;
            let store = Store::new(repo.clone());
            let oid = resolve_rev(&repo, Some(&rev))?;
            let commit = load_commit(&store, &oid)?;
            lvcs_core::checkout(&repo, &store, &commit.root, force)?;
            lvcs_core::write_head(&repo, &Head::Detached(oid))?;
        }
        Commands::Merge { rev } => {
            let repo = Repo::open(".")?;
            let _lock = RepoLock::acquire(repo.repo_dir())?;
            let store = Store::new(repo.clone());
            let oid = resolve_rev(&repo, Some(&rev))?;
            match merge(&repo, &store, &oid)? {
                MergeOutcome::Clean => {}
                MergeOutcome::Conflicts(paths) => {
                    for path in paths {
                        eprintln!("conflict: {}", path.display());
                    }
                    anyhow::bail!("merge conflicts");
                }
            }
        }
        Commands::Gc => {
            let repo = Repo::open(".")?;
            let _lock = RepoLock::acquire(repo.repo_dir())?;
            let store = Store::new(repo.clone());
            let result = gc(&repo, &store)?;
            if let Some(info) = result.pack_info {
                if use_color {
                    println!("\u{001b}[32mpacked\u{001b}[0m {}", info.pack_path.display());
                } else {
                    println!("packed {}", info.pack_path.display());
                }
            }
            println!("packed objects: {}", result.packed);
            println!("removed loose: {}", result.removed_loose);
            println!("removed packs: {}", result.removed_packs);
        }
        Commands::Fsck => {
            let repo = Repo::open(".")?;
            let store = Store::new(repo.clone());
            let result = fsck(&repo, &store)?;
            if !result.issues.is_empty() {
                for issue in &result.issues {
                    eprintln!("{issue}");
                }
                anyhow::bail!("fsck found issues");
            }
        }
        Commands::Serve {
            addr,
            repos,
            keys,
            cert,
            keyfile,
        } => {
            let addr: std::net::SocketAddr = addr.parse()?;
            let repos = parse_repos(repos)?;
            let keys = parse_keys(keys)?;
            let (cert, key) = if let (Some(cert), Some(keyfile)) = (cert, keyfile) {
                let cert = std::fs::read(cert)?;
                let key = std::fs::read(keyfile)?;
                let cert = rustls::pki_types::CertificateDer::from(cert);
                let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key);
                let key = rustls::pki_types::PrivateKeyDer::from(key);
                (cert, key)
            } else {
                generate_self_signed()?
            };
            let config = ServerConfigData {
                addr,
                repos,
                keys,
                cert,
                key,
            };
            lvcs_net::run_server(config).await?;
        }
        Commands::Fetch {
            addr,
            repo: repo_name,
            key_id,
            psk,
            remote,
        } => {
            let addr: std::net::SocketAddr = addr.parse()?;
            let repo = Repo::open(".")?;
            let known_hosts = repo.repo_dir().join("known_hosts");
            let psk = parse_psk(&psk)?;
            let config = ClientConfigData {
                addr,
                repo: repo_name,
                key_id,
                psk,
                known_hosts,
            };
            let mut client = connect_client(config).await?;
            client.fetch_into(&repo).await?;
            let refs = client.list_refs().await?;
            for (name, oid) in refs {
                let remote_ref = format!("refs/remotes/{remote}/{name}");
                lvcs_core::write_ref(&repo, PathBuf::from(remote_ref).as_path(), &oid)?;
            }
        }
        Commands::Push {
            addr,
            repo: repo_name,
            key_id,
            psk,
            refname,
            force,
        } => {
            let addr: std::net::SocketAddr = addr.parse()?;
            let repo = Repo::open(".")?;
            let known_hosts = repo.repo_dir().join("known_hosts");
            let psk = parse_psk(&psk)?;
            let config = ClientConfigData {
                addr,
                repo: repo_name,
                key_id,
                psk,
                known_hosts,
            };
            let mut client = connect_client(config).await?;
            let refs = client.list_refs().await?;
            let remote_old = refs
                .iter()
                .find(|(name, _)| name == &refname)
                .map(|(_, oid)| *oid);
            let head = lvcs_core::resolve_rev(&repo, Some("HEAD"))?;
            let update = RefUpdate {
                name: refname,
                old: remote_old,
                new: Some(head),
            };
            client.push_from(&repo, vec![update], force).await?;
        }
        Commands::ListRefs {
            addr,
            repo: repo_name,
            key_id,
            psk,
        } => {
            let addr: std::net::SocketAddr = addr.parse()?;
            let repo = Repo::open(".")?;
            let known_hosts = repo.repo_dir().join("known_hosts");
            let psk = parse_psk(&psk)?;
            let config = ClientConfigData {
                addr,
                repo: repo_name,
                key_id,
                psk,
                known_hosts,
            };

            let mut client = connect_client(config).await?;
            let refs = client.list_refs().await?;
            for (name, oid) in refs {
                println!("{oid} {name}");
            }
        }
    }

    Ok(())
}

fn default_author() -> String {
    let user = env::var("LVCS_AUTHOR")
        .ok()
        .or_else(|| env::var("USER").ok());
    let host = env::var("HOSTNAME").ok();
    match (user, host) {
        (Some(user), Some(host)) => format!("{user} <{user}@{host}>"),
        (Some(user), None) => user,
        (None, _) => "unknown".to_string(),
    }
}

fn color_enabled(mode: &ColorMode) -> bool {
    if env::var("NO_COLOR").is_ok() {
        return false;
    }
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => std::io::stdout().is_terminal(),
    }
}

fn print_commit_result(result: &CommitResult, color: bool) {
    let oid = result.oid.to_hex();
    if color {
        println!("\u{001b}[32m{oid}\u{001b}[0m");
    } else {
        println!("{oid}");
    }
}

fn print_log_entry(oid: &str, message: &str, decoration: &str, color: bool) {
    let deco = if decoration.is_empty() {
        "".to_string()
    } else if color {
        format!(" \u{001b}[33m({decoration})\u{001b}[0m")
    } else {
        format!(" ({decoration})")
    };
    if color {
        println!("* \u{001b}[36m{oid}\u{001b}[0m {message}{deco}");
    } else {
        println!("* {oid} {message}{deco}");
    }
}

fn build_decorations(
    repo: &Repo,
    refs: Vec<(PathBuf, lvcs_core::Oid)>,
) -> Result<HashMap<lvcs_core::Oid, Vec<String>>> {
    let mut out: HashMap<lvcs_core::Oid, Vec<String>> = HashMap::new();
    for (path, oid) in refs {
        let name = shorten_ref(&path);
        out.entry(oid).or_default().push(name);
    }
    match lvcs_core::read_head(repo)? {
        Head::Symbolic(path) => {
            if let Some(oid) = lvcs_core::read_ref(repo, &path)? {
                let name = format!("HEAD->{}", shorten_ref(&path));
                out.entry(oid).or_default().push(name);
            }
        }
        Head::Detached(oid) => {
            out.entry(oid).or_default().push("HEAD".to_string());
        }
    }
    Ok(out)
}

fn shorten_ref(path: &std::path::Path) -> String {
    let text = path.to_string_lossy();
    for prefix in ["refs/heads/", "refs/tags/", "refs/remotes/"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    text.to_string()
}

fn print_tree_item(
    item: &lvcs_core::TreeItem,
    long: bool,
    show_hash: bool,
    show_size: bool,
    color: bool,
) {
    let path = item.path.display();
    let name = if color {
        match item.entry.kind {
            lvcs_core::TreeEntryKind::Dir => format!("\u{001b}[34m{path}\u{001b}[0m"),
            lvcs_core::TreeEntryKind::Symlink => format!("\u{001b}[35m{path}\u{001b}[0m"),
            _ => path.to_string(),
        }
    } else {
        path.to_string()
    };
    if long {
        let mode = item.entry.mode;
        let size = item.size.unwrap_or(0);
        let oid = item.entry.oid.to_hex();
        println!("{mode:06o} {size:>8} {oid} {name}");
        return;
    }

    let mut parts = Vec::new();
    if show_size {
        parts.push(format!("{:<8}", item.size.unwrap_or(0)));
    }
    if show_hash {
        parts.push(item.entry.oid.to_hex());
    }
    if !parts.is_empty() {
        parts.push(name);
        println!("{}", parts.join(" "));
    } else {
        println!("{name}");
    }
}

fn parse_repos(values: Vec<String>) -> Result<HashMap<String, PathBuf>> {
    let mut out = HashMap::new();
    for value in values {
        let mut parts = value.splitn(2, '=');
        let name = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid repo entry"))?;
        let path = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid repo entry"))?;
        out.insert(name.to_string(), PathBuf::from(path));
    }
    Ok(out)
}

fn parse_keys(values: Vec<String>) -> Result<HashMap<String, KeyConfig>> {
    let mut out = HashMap::new();
    for value in values {
        let mut parts = value.splitn(3, ':');
        let key_id = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid key entry"))?;
        let psk_hex = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid key entry"))?;
        let role_str = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid key entry"))?;
        let role = match role_str {
            "readonly" => Role::ReadOnly,
            "readwrite" => Role::ReadWrite,
            _ => return Err(anyhow::anyhow!("invalid role")),
        };
        let psk = parse_psk(psk_hex)?;
        out.insert(key_id.to_string(), KeyConfig { psk, role });
    }
    Ok(out)
}

fn parse_psk(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(anyhow::anyhow!("psk must be 64 hex chars"));
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < 32 {
        let hi = hex_byte(bytes[i * 2])?;
        let lo = hex_byte(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn hex_byte(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(anyhow::anyhow!("invalid hex")),
    }
}
