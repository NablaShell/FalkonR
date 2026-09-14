# FalkonR

A single-binary, encrypted directory archiver written in Rust.

FalkonR seals a directory into a single vault file, then wipes the source.
It can also restore a vault back to disk. It supports an optional **duress
password**: entering it on unlock destroys the vault instead of restoring it.

Built with:

- **Tokio** — async file I/O and task orchestration
- **Rayon** — parallel directory scan and file processing
- **Argon2id** — password-based key derivation
- **ChaCha20-Poly1305** — authenticated encryption (AEAD), chunked
- **zstd** — streaming compression
- **clap** — command-line parsing
- **indicatif** — progress bars on stderr
- **rpassword** — hidden password input


```
falkonr -l <dir>     Seal a directory into a vault
falkonr -u <file>  Restore a vault
```

## Table of contents

1. [Usage](#usage)
2. [Duress password](#duress-password)
3. [Vault file format](#vault-file-format)
4. [Metadata layout](#metadata-layout)
5. [Encrypted blobs](#encrypted-blobs)
6. [Wipe semantics](#wipe-semantics)
7. [Security notes](#security-notes)
8. [Building](#building)
9. [License](#license)

## Usage

Seal a directory:

```
FalkonR --lock ./mydir -o ./mydir.bak
```

You will be prompted:

```
Password:
Confirm:
Do you want use duress password? [y/N]:
```

If you answer `y`, you are asked for the duress password twice:

```
Duress password:
Confirm duress:
```

Restore a vault:

```
falkonr --unlock ./mydir.bak
```

Restore writes the vault's root directory into the current working directory.

### Flags

| Flag | Short | Meaning |
|------|-------|---------|
| `--lock <DIR>`     | `-l`   | Seal the given directory into a vault |
| `--unlock <FILE>`  | `-u`   | Restore the given vault |
| `--output <PATH>`  | `-o`   | Output vault path (default: `vault.bak`) |
| `--verbose`        | `-v`   | Reserved for future verbose logging |
| `--help`           | `-h`   | Show help |

Exactly one of `-l` or `-u` must be given.

## Duress password

The duress password is entered interactively at **lock time**, not passed
via a CLI flag. It is stored as a **second encrypted slot** inside the vault
file. Nothing about the duress password is stored in plaintext, and there is
no SHA/MD5-style hash of it anywhere.

On unlock, FalkonR tries every slot in order:

1. If the entered password opens the **real** slot → normal restore.
2. If the entered password opens the **duress** slot → the tool prints
   `Duress password detected. Destroy vault?` and, on `y`, wipes the vault
   file before exiting.
3. If no slot opens → `wrong password`.

Because slot selection is based on whether the AEAD tag authenticates,
an attacker cannot tell "duress" apart from "wrong password" without
spending the same Argon2 time on every slot. There is no timing oracle
that reveals which password is the duress one.

## Vault file format

A vault is a flat binary file. All multi-byte integers are **big-endian**
unless stated otherwise.

```
+---------------------------+
| File header (8 bytes)     |
+---------------------------+
| Slot 0 (real)             |
+---------------------------+
| Slot 1 (duress, optional) |
+---------------------------+
```

### File header

```
offset  size  field         value
------  ----  ------------  -----------------------------
0       4     magic         0x0BADC0DE
4       2     version       2
6       1     slot_count    1 or 2
7       1     pad           0
```

`slot_count` is `1` if no duress password was set, `2` if one was.
`pad` is reserved and must be `0`.

### Slot

Every slot has the same shape:

```
offset  size       field       notes
------  ---------  ----------  -----------------------------------
0       16         salt        random, per-slot
16      8          slot_len    length in bytes of slot_bytes
24      slot_len   slot_bytes  see "Encrypted blobs" below
```

`slot_len` is the length of the **encrypted** blob that follows. It is
required so that slot 1 can be located without decrypting slot 0, and so
that the reader can try slot 0, fail, and continue to slot 1.

### Slot content

`slot_bytes` is the concatenation of independently-chunked
ChaCha20-Poly1305 records produced by `ChunkedWriter`. Each record is:

```
offset  size              field       notes
------  ---------------   ----------  ----------------------------------
0       4                 ct_len      length of ciphertext, big-endian
4       12                nonce       random per chunk
16      ct_len + 16       ct          ciphertext + Poly1305 tag
```

`ct_len` is the length of the plaintext chunk (before encryption). The
ciphertext stored is `ct_len + 16` bytes (Poly1305 tag is 16 bytes).

Chunk size is chosen at runtime, between 16 MiB and 1 GiB, based on
`MemAvailable` on Linux. The default fallback is 256 MiB.

## Metadata layout

Inside the decrypted, decompressed stream of a slot, the layout depends on
which slot it is.

### Real slot (slot 0)

The plaintext stream is the zstd-compressed archive body. After zstd
decompression, it looks like:

```
+--------------------------------------+
| Inner header (2 + 4 + N + 64 + 4 B)  |
+--------------------------------------+
| File entry 0                         |
| File entry 1                         |
| ...                                  |
| File entry K                         |
+--------------------------------------+
```

#### Inner header

```
offset  size      field         notes
------  --------  ------------  --------------------------------------
0       2         version       2
2       4         dir_name_len  length of the root directory name
6       N         dir_name      UTF-8, no slashes, no ".." (validated)
6+N     64        reserved      zero-filled (legacy SHA-512 slot)
6+N+64  4         magic         0x0BADC0DE
```

The `reserved` field is 64 bytes kept for layout compatibility with the
original Go implementation. FalkonR does not write a meaningful hash there
and does not verify it on unpack. It is always zero.

#### File entry

Each entry has a variable-length path and a 64-bit size, followed by the
raw file bytes:

```
offset  size    field      notes
------  ------  ---------  -----------------------------------------
0       4       path_len   length in bytes of the path
4       path_len path      UTF-8, forward slashes, relative to root
4+path_len  8   size       file size in bytes, big-endian
12+path_len  size  data    raw file contents
```

Entries are written in **lexicographic order of `path`**, so the archive
is deterministic given the same input directory.

Paths are validated on unpack:

- Not absolute.
- Must not contain `..` components.
- Must not contain `.` components other than a leading `./`.
- On Windows, backslashes are rejected.

The root `dir_name` is validated even more strictly: it must be a single
path component (no `/`, no `\`, no `.`, no `..`, not absolute).

### Duress slot (slot 1)

The plaintext stream is the zstd-compressed literal:

```
0x00 0x00 'D' 'U' 'R' 'E' 'S' 'S' 0x00 0x00
```

That is exactly 10 bytes: `b"\x00\x00DURESS\x00\x00"`. No file entries,
no inner header. On unlock, if a slot's first decrypted bytes match this
marker, FalkonR treats the slot as the duress slot and refuses to restore.

The marker is deliberately chosen so that it cannot collide with a real
archive: a real archive starts with `version = 2`, i.e. bytes `0x00 0x02`,
not `0x00 0x00`.

## Encrypted blobs

There are three levels of wrapping between a raw file on disk and the
decrypted archive body:

```
disk file
   |
   +-- file header (8 B, plaintext)
   |
   +-- slot 0
   |     |
   |     +-- salt (16 B, plaintext)
   |     +-- slot_len (8 B, plaintext)
   |     +-- slot_bytes  =  ChunkedWriter( ChaCha20-Poly1305( key ) )
   |                          applied over the output of:
   |                              zstd( archive body )
   |
   +-- slot 1 (optional)
         |
         +-- salt (16 B, plaintext)
         +-- slot_len (8 B, plaintext)
         +-- slot_bytes  =  ChunkedWriter( ChaCha20-Poly1305( duress_key ) )
                              applied over the output of:
                                  zstd( DURESS_MARKER )
```

### Key derivation

For each slot independently:

```
key = Argon2id(
    password = user password,
    salt     = slot.salt (16 bytes),
    memory   = 64 MiB,
    time     = 3,
    lanes    = 2,
    out      = 32 bytes,
)
```

The two slots use different salts, so even if the user picks the same
string for both passwords (which the tool forbids), the keys would still
differ.

### Chunked encryption

`slot_bytes` is not a single ChaCha20-Poly1305 message. It is a sequence
of chunks, each with its own random 12-byte nonce:

```
for each chunk:
    write big-endian u32 length of plaintext chunk
    write 12-byte random nonce
    write ChaCha20-Poly1305( plaintext_chunk, nonce, key )
```

There is no associated data (AAD) in the current version.

Why chunked at all: it bounds memory during decrypt to the size of the
largest chunk (max 1 GiB) rather than the size of the whole archive, and
it lets the reader stream without knowing the total plaintext length up
front.

Why a fresh nonce per chunk: ChaCha20-Poly1305 with a random 96-bit nonce
is safe up to roughly 2^32 messages per key. With a 1 GiB chunk size and
a 1 TiB vault, that is about 1024 messages — far below the limit.

### Compression

zstd with level 3, single-segment, streaming. Compression is applied
**before** encryption, on the whole plaintext stream. The compressor's
output is fed directly into the chunked encryptor; there is no separate
buffer of the compressed payload in memory.

On unpack, the order is reversed: chunked decrypt → zstd decompress →
parse archive body.

## Wipe semantics

After a successful `--lock`, the source directory is wiped:

- Every file is overwritten **three times** with:
  - pass 1: random bytes
  - pass 2: random bytes
  - pass 3: zeros
- Each pass is followed by `fsync`.
- The file is then unlinked.
- Finally, the directory tree is removed.

After a duress unlock, only the **vault file** is wiped, using the same
three-pass procedure, then unlinked.

### Honest limitations

FalkonR cannot guarantee physical erasure on:

- **SSDs / NVMe drives** — wear leveling, over-provisioning, and
  SLC caching mean that overwriting a logical block does not overwrite
  the physical block that previously held the data. The old block is
  marked stale and erased only at the next garbage-collection cycle.
- **Copy-on-write filesystems** (btrfs, ZFS, APFS) — writing to a file
  allocates new blocks and updates the tree; the old blocks remain
  reachable until the next GC, and remain **guaranteed reachable** if
  any snapshot references them.
- **Journaled filesystems with delayed allocation** — a power loss
  mid-wipe may leave the overwrite in the journal, not on disk.

What FalkonR **does** guarantee is **logical destruction**: the AEAD tag
of every chunk is invalidated, so the vault cannot be decrypted even if
the file's bytes are physically recoverable from stale blocks. A single
flipped bit in any ciphertext byte is enough to make Poly1305 reject the
chunk; thousands of flipped bits make recovery hopeless.

For guaranteed physical erasure, use full-disk encryption (LUKS, FileVault,
BitLocker) and destroy the master key (`cryptsetup luksErase`, …). That is
the only technique that works uniformly across SSDs, CoW filesystems, and
RAID.

## Security notes

- **Passwords are zeroized.** `SecureBytes` wraps `Vec<u8>` and clears it
  with `zeroize` on drop. The plaintext password never leaves that wrapper.
- **Keys are zeroized.** Derived 32-byte keys are dropped via `zeroize`
  after use.
- **No password hashes in the file.** Slot selection is based on whether
  the AEAD tag authenticates, not on comparing a stored hash. There is no
  offline oracle faster than Argon2id.
- **No plaintext metadata in the file.** Directory name, file names, file
  sizes, and file contents all live inside the encrypted, compressed
  stream. The only plaintext bytes are the 8-byte file header, the 16-byte
  per-slot salt, the 8-byte per-slot length, and the per-chunk 4-byte
  length + 12-byte nonce.
- **Path traversal is blocked.** Restore validates every path against
  `..`, absolute paths, and (on Windows) backslashes.
- **Duress is not a CLI argument.** The duress password is never passed
  on the command line, so it does not appear in `ps`, in shell history,
  or in `/proc/<pid>/cmdline`.

## Building

Requirements:

- Rust 1.75 or newer
- A C toolchain (for the `zstd` crate's bundled C sources)

```
cargo build --release
```

The binary is produced at:

```
target/release/falkonr
```

To strip it:

```
strip target/release/falkonr
```

## License

Apache-2.0
