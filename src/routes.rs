//! HTTP routes for creating and validating signed receipts.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::crypto::{sign_bytes, verify_bytes};
use crate::model::{compute_block_hash, hash_concat, Block};
use crate::AppState;

/// Accept either raw text (input/output) or pre-hashed fields (input_hash/output_hash).
#[derive(Deserialize)]
pub struct ReceiptInput {
    #[serde(default)]
    pub input: Option<String>,
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub input_hash: Option<String>,
    #[serde(default)]
    pub output_hash: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>, // allow client-provided, else server fills
}

#[derive(Serialize)]
pub struct ReceiptOutput {
    pub id: u64,
    pub input_hash: String,
    pub output_hash: String,
    pub timestamp: String,
    pub signature_hex: String,
    pub prev_hash_hex: String,
    pub block_hash_hex: String,
    pub verified: bool,
}

/// POST /receipt
pub async fn add_receipt(
    State(state): State<AppState>,
    Json(payload): Json<ReceiptInput>,
) -> Result<Json<ReceiptOutput>, (StatusCode, String)> {
    // 1) Compute hashes if raw fields provided
    let in_hash = match (payload.input_hash, payload.input) {
        (Some(h), _) if !h.trim().is_empty() => h,
        (_, Some(raw)) if !raw.trim().is_empty() => hash_concat(&[raw.as_bytes()]),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "must provide input or input_hash".into(),
            ))
        }
    };

    let out_hash = match (payload.output_hash, payload.output) {
        (Some(h), _) if !h.trim().is_empty() => h,
        (_, Some(raw)) if !raw.trim().is_empty() => hash_concat(&[raw.as_bytes()]),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "must provide output or output_hash".into(),
            ))
        }
    };

    // 2) Timestamp (RFC3339). If client provided, we trust it as-is.
    let ts = match payload.timestamp {
        Some(t) if !t.trim().is_empty() => t,
        _ => OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "time format error".to_string(),
            )
        })?,
    };

    // 3) Sign (hash(input_hash||output_hash||timestamp))
    let to_sign = hash_concat(&[in_hash.as_bytes(), out_hash.as_bytes(), ts.as_bytes()]);
    let sig = sign_bytes(&state.keypair.signing, to_sign.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    // 4) Verify immediately
    let verified_now = verify_bytes(&state.keypair.verifying, to_sign.as_bytes(), &sig);
    if !verified_now {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "signature verify failed".into(),
        ));
    }

    // 5) Assemble new block header
    let mut guard = state.ledger.lock().unwrap();
    let id = guard.blocks.len() as u64 + 1;
    let prev_hash = guard
        .blocks
        .last()
        .map(|b| b.block_hash_hex.clone())
        .unwrap_or_default();

    let mut block = Block {
        id,
        input_hash: in_hash.clone(),
        output_hash: out_hash.clone(),
        timestamp: ts.clone(),
        signature_hex: sig_hex.clone(),
        prev_hash_hex: prev_hash.clone(),
        block_hash_hex: String::new(),
    };
    block.block_hash_hex = compute_block_hash(&block);

    // 6) Persist
    guard.blocks.push(block.clone());
    drop(guard);
    if let Err(e) = crate::storage::save_block(&state.data_dir, &block) {
        eprintln!("Failed to save block: {e}");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "persist failed".into()));
    }

    Ok(Json(ReceiptOutput {
        id,
        input_hash: in_hash,
        output_hash: out_hash,
        timestamp: ts,
        signature_hex: sig_hex,
        prev_hash_hex: prev_hash,
        block_hash_hex: block.block_hash_hex,
        verified: true,
    }))
}

/// GET /receipt/:id
pub async fn get_receipt(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<ReceiptOutput>, (StatusCode, String)> {
    let guard = state.ledger.lock().unwrap();
    let idx = id
        .checked_sub(1)
        .ok_or((StatusCode::NOT_FOUND, "not found".into()))?;
    let block = guard
        .blocks
        .get(idx as usize)
        .ok_or((StatusCode::NOT_FOUND, "not found".into()))?;

    // re-verify signature over (input_hash||output_hash||timestamp)
    let to_sign = hash_concat(&[
        block.input_hash.as_bytes(),
        block.output_hash.as_bytes(),
        block.timestamp.as_bytes(),
    ]);
    let sig_bytes = hex::decode(&block.signature_hex).unwrap_or_default();
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored signature invalid".into(),
        ));
    };
    let verified = verify_bytes(&state.keypair.verifying, to_sign.as_bytes(), &sig);

    Ok(Json(ReceiptOutput {
        id: block.id,
        input_hash: block.input_hash.clone(),
        output_hash: block.output_hash.clone(),
        timestamp: block.timestamp.clone(),
        signature_hex: block.signature_hex.clone(),
        prev_hash_hex: block.prev_hash_hex.clone(),
        block_hash_hex: block.block_hash_hex.clone(),
        verified,
    }))
}

/// GET /receipts
pub async fn list_receipts(
    State(state): State<AppState>,
) -> Result<Json<Vec<Block>>, (StatusCode, String)> {
    let guard = state.ledger.lock().unwrap();
    Ok(Json(guard.blocks.clone()))
}

/// GET /validate — verify all signatures and linkages; returns { ok, errors[] }
#[derive(Serialize)]
pub struct ValidateResp {
    pub ok: bool,
    pub errors: Vec<String>,
}
pub async fn validate_chain(State(state): State<AppState>) -> Json<ValidateResp> {
    let guard = state.ledger.lock().unwrap();
    let mut errors = vec![];

    for (i, b) in guard.blocks.iter().enumerate() {
        // linkage
        if i > 0 {
            let prev = &guard.blocks[i - 1];
            if b.prev_hash_hex != prev.block_hash_hex {
                errors.push(format!("block {} prev_hash mismatch", b.id));
            }
        } else if !b.prev_hash_hex.is_empty() {
            errors.push("genesis prev_hash should be empty".to_string());
        }

        // block hash
        let recomputed = crate::model::compute_block_hash(b);
        if recomputed != b.block_hash_hex {
            errors.push(format!("block {} block_hash mismatch", b.id));
        }

        // signature
        let to_sign = hash_concat(&[
            b.input_hash.as_bytes(),
            b.output_hash.as_bytes(),
            b.timestamp.as_bytes(),
        ]);
        let Ok(sig) = Signature::from_slice(&hex::decode(&b.signature_hex).unwrap_or_default())
        else {
            errors.push(format!("block {} signature decode failed", b.id));
            continue;
        };
        if !verify_bytes(&state.keypair.verifying, to_sign.as_bytes(), &sig) {
            errors.push(format!("block {} signature invalid", b.id));
        }
    }

    Json(ValidateResp {
        ok: errors.is_empty(),
        errors,
    })
}

/// GET /pubkey — hex verifying key
#[derive(Serialize)]
pub struct PubKeyResp {
    pub pubkey_hex: String,
}
pub async fn pubkey(State(state): State<AppState>) -> Json<PubKeyResp> {
    Json(PubKeyResp {
        pubkey_hex: hex::encode(state.keypair.verifying.to_bytes()),
    })
}

/// GET /health
#[derive(Serialize)]
pub struct Health {
    pub status: &'static str,
}
pub async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

/// GET /version
#[derive(Serialize)]
pub struct Version {
    pub version: &'static str,
    pub git_sha: Option<&'static str>,
}
pub async fn version() -> Json<Version> {
    Json(Version {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: option_env!("GIT_SHA"),
    })
}
