# ViperFin — TLS Fingerprinting Tool

> **Coded by Egyan**

ViperFin is a JA3/JA3S TLS fingerprinting tool written in Go. Identifies what
software is making TLS connections by analyzing the raw ClientHello message —
no ML, no APIs, pure protocol analysis.

Used defensively by threat intel platforms (Salesforce, Cloudflare, Fastly) to
detect malware C2 channels. Used offensively to identify what TLS stack a server
expects from clients.

---

## How JA3 Works

Every TLS connection starts with a **ClientHello** message. Before any encryption
happens, the client announces:

- Which **TLS version** it supports
- Which **cipher suites** it can use (ordered by preference)
- Which **extensions** it wants to use
- Which **elliptic curves** it supports
- Which **EC point formats** it supports

Different clients produce different combinations. Chrome, Firefox, curl, Python
requests, and Cobalt Strike all produce distinct ClientHello messages — even when
connecting to the same server.

**JA3** takes these five fields, joins them as a comma-separated string, and MD5
hashes the result:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
769,47-53-5-10-49161,0-10-11,23-24,0
→ MD5 → a0e9f5d64349fb13191bc781f81f42e1
```

GREASE values (RFC 8701 — random values browsers insert to prevent ossification)
are excluded before hashing.

**JA3S** is the server-side equivalent — fingerprints the ServerHello response.
The combination of JA3 + JA3S identifies not just what client is connecting but
also what server infrastructure is being used (useful for C2 detection).

---

## Install

Requirements: Go 1.21+

```bash
git clone <repo>
cd viperfin
chmod +x build.sh
./build.sh
```

Or just:
```bash
go build -o viperfin .
```

No external dependencies — uses only Go stdlib.

---


---

## Windows Quick Start (after cross-compiling from Kali)

Once you have `viperfin.exe` built on Kali and transferred to Windows:

### Step 1 — Open Command Prompt
Press `Win + R`, type `cmd`, press Enter.

### Step 2 — Navigate to the folder
```cmd
cd "C:\My Projects\Projects\ViperFin"
```

### Step 3 — Run it against any website
```cmd
viperfin.exe client google.com:443
```

Just replace `google.com` with any website you want to check:
```cmd
viperfin.exe client facebook.com:443
viperfin.exe client github.com:443
viperfin.exe client yourbank.com:443
```

The `:443` at the end is always the same for normal websites — it means "use the secure HTTPS connection". You don't need to change it.

---

### What the output tells you

| Section | What it means |
|---|---|
| **TLS Version** | The security protocol the website is using — TLS 1.3 is the latest and most secure |
| **Cert Subject** | Which domain the security certificate belongs to |
| **Cert Issuer** | Who issued the security certificate (e.g. Google, DigiCert) |
| **Cert Expiry** | When the certificate expires — green means fine, red means expiring soon |
| **JA3 Hash** | A unique fingerprint of *your* connection — like a digital ID for how your computer connects |
| **JA3S Hash** | A unique fingerprint of the *server's* response |
| **Threat Intelligence** | Checks if either fingerprint matches known malware or hacking tools |

### What to look for

- ✅ `TLS 1.3` — good, modern and secure
- ✅ Cert Expiry shown in green — certificate is valid
- ⚠️ Cert Expiry shown in red — certificate is expiring soon or expired
- 🚨 Threat Intelligence shows a match — the connection fingerprint matches known malware or a hacking tool

## Usage

### Client Mode
Connect to a TLS server and fingerprint yourself:

```bash
# Basic
./viperfin client google.com:443

# Verbose — shows all cipher suites, extensions, curves
./viperfin client example.com:443 --verbose

# JSON output (pipe-friendly)
./viperfin client 10.0.0.1:8443 --json

# Non-standard port, skip cert verify
./viperfin client internal.corp:8443 --insecure
```

**What it shows:**
- Your JA3 hash (what you look like to the server)
- The server's JA3S hash
- Negotiated TLS version and cipher suite
- Server certificate details + expiry countdown
- Threat intel match from local database

### Server Mode
Listen for incoming TLS connections and fingerprint every client:

```bash
# Start on default port 4443
./viperfin server

# Custom port
./viperfin server --port 8443

# JSON output (for piping to a log file)
./viperfin server --port 4443 --json >> fingerprints.jsonl
```

Then connect from another terminal to test:
```bash
curl -k https://localhost:4443          # will show curl's JA3
python3 -c "import urllib.request; urllib.request.urlopen('https://localhost:4443')"
openssl s_client -connect localhost:4443
```

**Use case:** Set this up on a server you control. Any client that connects
gets fingerprinted. Useful for:
- Red team: Understand what your tools look like to defenders
- Blue team: Identify unexpected clients on your network
- Research: Collect JA3 hashes from production traffic

### Lookup Mode
Query the local signature database:

```bash
# Look up a specific hash
./viperfin lookup 6bea65232d17d4884c427918d6c3abf0

# List all signatures
./viperfin lookup --list

# Filter by threat level
./viperfin lookup --list --threat malicious
./viperfin lookup --list --threat suspicious
```

---

## Signature Database

The local database (`db/ja3_signatures.json`) contains known JA3 hashes for:

| Category | Examples |
|---|---|
| Browsers | Chrome, Firefox, Safari, Tor Browser |
| Tools | curl, wget, Python requests, OpenSSL, Go net/http |
| Pentest | Metasploit, Nmap |
| Malware C2 | Cobalt Strike, Sliver, Emotet, TrickBot, Dridex, QakBot, Brute Ratel |
| Scanners | Masscan, Shodan |

### Extending the database

Edit `db/ja3_signatures.json` and add entries:

```json
{
  "hash": "your_md5_hash_here",
  "label": "Descriptive name",
  "category": "browser|tool|scanner|pentest_tool|malware_c2",
  "threat_level": "benign|info|suspicious|malicious",
  "notes": "Context about this fingerprint"
}
```

Community databases:
- https://ja3er.com — crowdsourced JA3 database
- https://github.com/salesforce/ja3 — original JA3 implementation + database

---

## TLS Internals Reference

### ClientHello Structure (what we parse)

```
TLS Record Header (5 bytes)
  ├── Content Type: 0x16 (Handshake)
  ├── Legacy Version: 0x0303 (TLS 1.2, even for TLS 1.3)
  └── Length: 2 bytes

Handshake Header (4 bytes)
  ├── Type: 0x01 (ClientHello)
  └── Length: 3 bytes

ClientHello Body
  ├── Client Version: 2 bytes  ← JA3 field 1
  ├── Random: 32 bytes
  ├── Session ID: variable
  ├── Cipher Suites: variable  ← JA3 field 2
  ├── Compression Methods: variable
  └── Extensions: variable
        ├── server_name (0)    → extracts SNI hostname
        ├── supported_groups (10) ← JA3 field 4 (elliptic curves)
        ├── ec_point_formats (11) ← JA3 field 5
        ├── signature_algorithms (13)
        ├── supported_versions (43) → actual TLS version for TLS 1.3
        └── ... (all type IDs form JA3 field 3)
```

### Why GREASE is Excluded

RFC 8701 defines a set of "GREASE" values (0x0A0A, 0x1A1A, ..., 0xFAFA) that
browsers randomly insert into cipher suite lists and extension lists. The purpose
is to ensure TLS implementations don't break when they see unknown values.

Since GREASE values change per connection (by design), they would make JA3
fingerprints non-deterministic for browsers. JA3 filters them out so the same
browser produces the same hash across connections.

---

## Project Structure

```
viperfin/
├── main.go              # CLI entry point
├── go.mod               # Module definition (stdlib only)
├── build.sh             # Cross-compile script
├── cmd/
│   ├── client.go        # `viperfin client` subcommand
│   ├── server.go        # `viperfin server` subcommand
│   └── lookup.go        # `viperfin lookup` subcommand
├── tls/
│   ├── ja3.go           # JA3/JA3S hash computation + cipher/extension names
│   ├── parser.go        # Raw ClientHello/ServerHello byte parser
│   ├── capture.go       # Client mode — captureConn wrapper
│   └── server.go        # Server mode — listener + self-signed cert generation
├── db/
│   ├── signatures.go    # Database loader (embedded JSON, Go embed)
│   └── ja3_signatures.json  # Known JA3 hashes
└── report/
    └── output.go        # Terminal formatting + JSON output
```

---

## Extending This Tool

Ideas for what to build on top:
- **PCAP mode:** Parse `.pcap` files offline using `gopacket` — extract JA3 from
  captured traffic without needing a live connection
- **Continuous monitor:** Run server mode + pipe JSON to a file, build a
  simple dashboard that reads the JSONL file
- **JA3 database sync:** Pull latest hashes from ja3er.com API and merge into
  local database
- **Proxy mode:** MITM proxy that fingerprints every HTTPS connection passing
  through it — useful for analyzing app traffic

---

## References

- Original JA3 paper: https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
- RFC 8701 (GREASE): https://www.rfc-editor.org/rfc/rfc8701
- TLS 1.3 spec: https://www.rfc-editor.org/rfc/rfc8446
- Wireshark TLS dissector (for comparison): https://wiki.wireshark.org/TLS
