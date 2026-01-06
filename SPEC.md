# LVCS v1.0 Specification (Draft)

## Repository Layout

- `.repo/` metadata directory
- `.repo/objects/` loose content-addressed objects
- `.repo/pack/` pack + index files
- `.repo/refs/` references (branches, tags, remotes)
- `.repo/HEAD` current reference
- `.repo/MERGE_STATE` merge state (when conflicts exist)
- `.repo/reflog` server-side reflog entries

## Object IDs

- Hash: BLAKE3 over canonical uncompressed payload bytes
- Domain separation prefix:
  - `lvcs:chunk\0`
  - `lvcs:manifest\0`
  - `lvcs:tree\0`
  - `lvcs:commit\0`

## Chunking

- Fixed-size chunks: 1 MiB (`1048576` bytes)
- Last chunk may be smaller

## Objects

### chunk

- Payload: raw bytes

### manifest

- Payload (big-endian):
  - `u64 file_len`
  - `u32 mode`
  - `u32 chunk_size`
  - `u64 chunk_count`
  - `chunk_count * [32-byte chunk_oid]`

### tree

- Entries sorted by byte-wise name
- Payload (big-endian):
  - `u64 entry_count`
  - For each entry:
    - `u64 name_len` + `name` bytes
    - `u8 kind` (1=file, 2=dir, 3=symlink)
    - `u32 mode`
    - `32-byte oid`

### commit

- Payload (big-endian):
  - `32-byte root_tree_oid`
  - `u64 parent_count`
  - `parent_count * [32-byte parent_oid]`
  - `u64 author_len` + `author` bytes (UTF-8)
  - `i64 timestamp` (unix seconds)
  - `u64 message_len` + `message` bytes (UTF-8)

## Loose Objects

- File format:
  - `LVCSOBJ1` magic (8 bytes)
  - `u8 kind`
  - `u64 payload_len`
  - `zstd`-compressed payload
- OID computed from uncompressed payload + domain prefix

## Pack Format

- Pack file:
  - `LVCSPACK` magic (8 bytes)
  - `u32 version` (1)
  - `u64 object_count`
  - For each object:
    - `u8 kind`
    - `32-byte oid`
    - `u64 payload_len`
    - `u64 compressed_len`
    - `zstd`-compressed payload
  - `32-byte pack_hash` (BLAKE3 of all prior bytes)
- Index file:
  - `LVCSPIDX` magic (8 bytes)
  - `u32 version` (1)
  - `u64 entry_count`
  - For each entry:
    - `32-byte oid`
    - `u64 pack_offset`

## Ignore Rules

- Always ignore `.repo/**`
- `.lvcsignore` uses gitignore semantics (`#` comments, `!` negation, `**`, `/` anchors)

## Merge State

- `.repo/MERGE_STATE` content:
  - `base <oid>`
  - `other <oid>`

## Reflog (Server)

- `.repo/reflog` lines:
  - `unix_ts key_id ref old_oid new_oid force_flag`

## Network Protocol (QUIC)

### Transport

- QUIC via `quinn`
- One bidirectional stream per session

### Auth

- `AUTH1`: `key_id` + `client_nonce`
- `AUTH2`: `server_nonce` + `MAC` (BLAKE3 keyed hash)
- `AUTH3`: `MAC`
- Session key derived via `BLAKE3(keyed, DOMAIN_SESSION + nonces)`

### Messages (framed)

- 4-byte length prefix (big-endian)
- Message types:
  - `Auth1`, `Auth2`, `Auth3`, `Hello`, `HelloOk`, `Error`
  - `ListRefs`, `ListRefsResp`
  - `Fetch`, `FetchResp`
  - `Push`, `PushResp`

### Push Policy

- Update tuple: `(ref, old, new, force)`
- Non-fast-forward rejected unless `force`
- Server verifies:
  - pack hash
  - object OIDs via recomputation
  - graph connectivity via fsck
  - reflog append

## CLI

- `lvcs init` initializes a repository
- `lvcs commit -m <msg>` snapshots worktree
- `lvcs log` shows commit history with decorations
- `lvcs tree [--long|--hash|--size]` shows snapshot tree
- `lvcs checkout [--force] <rev>` restores snapshot
- `lvcs merge <rev>` performs 3-way merge
- `lvcs gc` repacks reachable objects
- `lvcs fsck` validates repository
- `lvcs serve` runs QUIC server
- `lvcs fetch` and `lvcs push` sync with server
