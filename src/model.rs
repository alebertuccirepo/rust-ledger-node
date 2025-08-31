//! Data model for verifiable receipts and the in-memory ledger.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// 1-indexed sequential ID.
    pub id: u64,
    /// SHA-256 hex of input payload (server- or client-computed).
    pub input_hash: String,
    /// SHA-256 hex of output payload (server- or client-computed).
    pub output_hash: String,
    /// RFC3339 timestamp string.
    pub timestamp: String,
    /// Ed25519 signature (hex) over hash(input_hash || output_hash || timestamp).
    pub signature_hex: String,
    /// SHA-256 hex of the previous block header (empty for genesis).
    pub prev_hash_hex: String,
    /// SHA-256 hex of this block header (id, input/output hashes, timestamp, signature, prev).
    pub block_hash_hex: String,
}

/// Simple container for the chain.
#[derive(Debug, Default)]
pub struct Ledger {
    pub blocks: Vec<Block>,
}

impl Ledger {
    pub fn next_id(&self) -> u64 {
        (self.blocks.len() as u64) + 1
    }
}

/// Hash inputs (concatenate as bytes, SHA-256) and return lowercase hex.
pub fn hash_concat(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hex::encode(hasher.finalize())
}

/// Compute a block hash from its header fields.
/// Included: id, input_hash, output_hash, timestamp, signature_hex, prev_hash_hex.
pub fn compute_block_hash(b: &Block) -> String {
    hash_concat(&[
        &b.id.to_le_bytes(),
        b.input_hash.as_bytes(),
        b.output_hash.as_bytes(),
        b.timestamp.as_bytes(),
        b.signature_hex.as_bytes(),
        b.prev_hash_hex.as_bytes(),
    ])
}
