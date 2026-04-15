<div align="center">

# FLIP

### *Freenet IRC-Like Protocol*

*Anonymous, censorship-resistant IRC-style chat — routed entirely through Freenet.*

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0)
[![C++14](https://img.shields.io/badge/C++-14-00599C.svg)](https://en.cppreference.com/w/cpp/14)
[![CMake](https://img.shields.io/badge/Build-CMake-064F8C.svg)](https://cmake.org/)
[![Freenet](https://img.shields.io/badge/Network-Freenet%20FCPv2-3a7bcc.svg)](https://freenetproject.org/)

*A daemon that bridges your IRC client to the Freenet darknet. No servers. No logs. No censorship.*

---

</div>

## About

FLIP sits between your IRC client and Freenet. It speaks standard IRC to your client and FCPv2 to Freenet. Messages are stored as SSK-signed inserts — nobody controls the channel, nobody can delete the history, and nobody can trace who said what.

Each user generates an RSA identity. Private messages are RSA-encrypted end-to-end. Channel messages are signed but readable by anyone who polls the SSK (channel-level encryption is planned — see `TODO.md`).

This is a **patched fork** of the original FLIP 0.3.1 source by SomeDude. Patches applied:

- RSA OAEP padding enforced (PKCS#1 v1.5 legacy mode preserved behind `m_legacycompat` flag)
- Constant-time RSA comparison to prevent timing side-channels
- CTCP reply suppression (prevent client auto-reply leaking presence)
- mbedTLS updated to current release
- CMake modernized (minimum 3.5, policy CMP0003)

---

## Architecture

```
Your IRC client  ──IRC──►  FLIP daemon  ──FCPv2──►  Freenet node
                                │
                           SQLite3 DB
                        (identities, messages)
```

FLIP runs as a local daemon. Point your IRC client at `localhost:6667` (default). FLIP maintains its own identity store, fetches/inserts messages from Freenet, and presents them as IRC traffic.

---

## Features

<table>
<tr>
<td width="50%">

### Messaging
- IRC channel chat over Freenet SSKs
- End-to-end encrypted private messages (RSA)
- Legacy channel support (`/legacy #channel`) with PKCS#1 v1.5
- Message edition polling for updates
- Persistent message store (SQLite3)

</td>
<td width="50%">

### Identity
- RSA key pair generation per identity
- Automatic identity announcement & discovery
- Unkeyed (anonymous) identity creation
- Identity requester for new peers
- Multiple local identities supported

</td>
</tr>
<tr>
<td width="50%">

### Connectivity
- Standard FCPv2 to any Freenet node
- Optional TLS-over-FCP (`-DFCPSSL=ON`)
- Works with local or remote Freenet node
- Threaded connection handling (pthreads)
- FreeBSD, Linux, Windows, Solaris support

</td>
<td width="50%">

### Optional Java Plugin
- `plugin/` directory contains a Freenet Java plugin variant
- Built separately with `-DBUILD_PLUGIN=ON`
- Embeds FLIP functionality inside the Freenet node itself

</td>
</tr>
</table>

---

## Building

### Prerequisites

| Package | Notes |
|---------|-------|
| C++14 compiler | GCC 5+ or Clang 3.4+ |
| CMake 3.5+ | Build system |
| pthreads | System library |
| SQLite3 | Bundled — no system install needed |
| mbedTLS | Bundled in `libs/mbedtls/` |
| dlib | Bundled in `libs/dlib/` |
| librock | Bundled in `libs/librock/` |

All vendored libraries are included in-tree. You need only a compiler, CMake, and pthreads.

### Linux / FreeBSD

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

With SSL FCP support enabled (default):

```bash
cmake -DFCPSSL=ON ..
make -j$(nproc)
```

With system SQLite3 instead of bundled:

```bash
cmake -DUSE_BUNDLED_SQLITE=OFF ..
make -j$(nproc)
```

### Windows

```bash
mkdir build && cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
```

### Sanitizer build (debugging)

```bash
mkdir build-sanitize && cd build-sanitize
cmake -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined" ..
make -j$(nproc)
```

---

## Usage

1. Start your Freenet node and note its FCP port (default: `9481`).
2. Run FLIP:
   ```bash
   ./flip
   ```
   On first run, FLIP generates a config file (`flip.ini` or similar) and an RSA identity.
3. Connect your IRC client to `localhost:6667`.
4. Join a Freenet channel:
   ```
   /join #yourchannel
   ```
   FLIP will begin inserting/fetching via Freenet SSKs. New messages may take several minutes to appear depending on Freenet network latency.

### Private messages

```
/msg SomeFreenetUser hello
```

Private messages are RSA-encrypted with the recipient's public key before insert.

### Legacy channels

For compatibility with older FLIP clients that only support PKCS#1 v1.5:

```
/join #legacy:channelname
```

---

## Configuration

FLIP stores state in `flip.db3` (SQLite3) and logs to `flip.log`. On first run it will prompt for FCP host/port and IRC listen port if no config file is found.

Key settings (set in the config or at first-run prompt):

| Setting | Default | Description |
|---------|---------|-------------|
| FCP host | `127.0.0.1` | Freenet node FCP address |
| FCP port | `9481` | Freenet node FCP port |
| IRC port | `6667` | Local IRC listen port |
| SSL FCP | enabled | TLS for FCP connection (requires `FCPSSL=ON` build) |

---

## Credits

| Contributor | Role |
|-------------|------|
| **SomeDude** | Original author (2013–2026) |
| **blubskye** | Patched fork — security hardening, mbedTLS update, CTCP suppression |

---

## License

GNU General Public License v2.0. See [LICENSE](LICENSE) for the full text.

```
Copyright (C) 2013-2026  SomeDude
              2026        blubskye and contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
```
