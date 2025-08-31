//! Disk persistence for blocks (JSON per file).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::model::Block;

/// Ensure that the given directory exists (create recursively if needed).
pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Compute the JSON filename for a block id.
pub fn block_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("block_{id}.json"))
}

/// Write a block to disk as `block_<id>.json` (pretty-printed).
pub fn save_block(dir: &Path, block: &Block) -> std::io::Result<()> {
    ensure_dir(dir)?;
    let p = block_path(dir, block.id);
    let mut f = File::create(p)?;
    let json = serde_json::to_string_pretty(block).expect("block json");
    f.write_all(json.as_bytes())?;
    Ok(())
}

/// Load all `*.json` files from the directory into memory and sort by id.
pub fn load_blocks(dir: &Path) -> std::io::Result<Vec<Block>> {
    ensure_dir(dir)?;
    let mut out = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let mut f = File::open(&p)?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;
        if let Ok(block) = serde_json::from_str::<Block>(&buf) {
            out.push(block);
        }
    }
    out.sort_by_key(|b| b.id);
    Ok(out)
}
