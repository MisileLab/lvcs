# LVCS (Lambda VCS)

LVCS is a snapshot-based version control system implemented in Rust.
This repository targets a durable v1.0 with content-addressed storage, packs, and QUIC remotes.

## Build

```
cargo build
```

## Local Usage

```
lvcs init
lvcs commit -m "message"
lvcs log
lvcs tree --long
lvcs checkout <rev>
lvcs merge <rev>
lvcs gc
lvcs fsck
```

## Remote Usage

Start a server with repo and key entries:

```
lvcs serve \
  --repo origin=/path/to/repo \
  --key key1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:readwrite
```

Fetch and push:

```
lvcs fetch --addr 127.0.0.1:7447 --repo origin --key-id key1 --psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
lvcs push --addr 127.0.0.1:7447 --repo origin --key-id key1 --psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --refname refs/heads/main
```
