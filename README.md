# Rust Ledger Node 
![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

# Description
A tiny Rust service that issues Ed25519-signed receipts for computations and stores them in a tamper-evident chain (prev-hash + block-hash), with key persistence and full-chain validation.

# Features (bullets only)

Ed25519 signing (over hash(input_hash || output_hash || timestamp))
Tamper evidence via prev_hash_hex and block_hash_hex
JSON block persistence in ./data
Key persistence in data/key.bin
Endpoints: /receipt, /receipt/{id}, /receipts, /validate, /pubkey, /health, /version

# Quickstart
cargo build
cargo run
# http://127.0.0.1:3000

# API (compact and specific)

POST /receipt
Body options:

{ "input": "...", "output": "..." }

{ "input_hash": "<sha256hex>", "output_hash": "<sha256hex>", "timestamp": "<RFC3339>" }
Returns: block header + verified: true

GET /receipt/{id} → block + verified

GET /receipts → array of blocks

GET /validate → { ok: bool, errors: string[] }

GET /pubkey → { pubkey_hex: string }

GET /health → { status: "ok" }

GET /version → { version, git_sha }

# Examples (PowerShell-native so Windows can copy paste)
# Create a receipt (server hashes)
$body = @{ input = "hello"; output = "world" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:3000/receipt -ContentType 'application/json' -Body $body | Format-List

# Read it back
Invoke-RestMethod -Uri http://127.0.0.1:3000/receipt/1 | Format-List

# Validate the chain
Invoke-RestMethod -Uri http://127.0.0.1:3000/validate | Format-List

# Public key
Invoke-RestMethod -Uri http://127.0.0.1:3000/pubkey


(If you prefer curl: use curl.exe on Windows, not curl.)

# How it works summary

Server hashes raw input/output if provided, or accepts pre-hashed values.

Signs hash(input_hash || output_hash || timestamp) with Ed25519.

Builds a block with prev_hash_hex, computes block_hash_hex, persists JSON.

/validate recomputes signatures and linkages to detect tampering.

# Operational notes

Key file: data/key.bin (32-byte seed). Don’t commit it.

Data files: data/block_<id>.json (pretty JSON).

Concurrency: protected via a Mutex (simple and safe for this demo).

Restart behavior: same public key, previously created blocks still verify.

# Roadmap (future additions)

Optional: P2P gossip to replicate blocks

Optional: Merkle proofs for subsets

Optional: Persist to SQLite or Sled

Optional: Auth/rate limiting via tower layers
