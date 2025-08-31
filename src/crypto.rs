//! Cryptographic helpers: Ed25519 key handling, signing and verification.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

/// Simple in-memory keypair bundle used by the server state.
pub struct Keypair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

/// Generate a fresh Ed25519 keypair using the OS RNG.
pub fn generate_keypair() -> Keypair {
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    Keypair { signing, verifying }
}

/// Sign arbitrary bytes with the provided signing key.
pub fn sign_bytes(signing: &SigningKey, msg: &[u8]) -> Signature {
    signing.sign(msg)
}

/// Verify a message/signature pair using the provided verifying key.
pub fn verify_bytes(verifying: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    verifying.verify(msg, sig).is_ok()
}

/// Save (overwrite) the private key seed (32 bytes) to disk.
pub fn save_key(path: &Path, signing: &SigningKey) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = File::create(path)?;
    let raw: [u8; 32] = signing.to_bytes();
    f.write_all(&raw)?;
    Ok(())
}

/// Load the private key seed (32 bytes) if present; else return `None`.
/// Returns `None` for malformed files as a defensive measure.
pub fn load_key(path: &Path) -> std::io::Result<Option<SigningKey>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    if buf.len() != 32 {
        return Ok(None);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&buf);
    Ok(Some(SigningKey::from_bytes(&seed)))
}
