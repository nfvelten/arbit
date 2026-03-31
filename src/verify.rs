//! Supply-chain security: verify MCP server binaries before spawning.
//!
//! Two independent checks, both optional:
//! 1. **SHA-256 hash pin** — computed from the binary on disk, compared to `config.sha256`.
//! 2. **Cosign bundle** — delegates to the `cosign verify-blob` CLI (must be on PATH).
//!
//! Either check failing is fatal: `verify_binary` returns `Err` and the gateway refuses to start.

use crate::config::BinaryVerifyConfig;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Resolve `cmd` to an absolute path, then run all configured checks.
/// Returns `Ok(())` if all enabled checks pass, `Err` otherwise.
pub async fn verify_binary(cmd: &str, cfg: &BinaryVerifyConfig) -> anyhow::Result<()> {
    let path = resolve_binary(cmd)?;
    tracing::info!(binary = %path.display(), "verifying server binary");

    if let Some(expected) = &cfg.sha256 {
        let path2 = path.clone();
        let actual = tokio::task::spawn_blocking(move || sha256_hex(&path2)).await??;
        let expected = expected.to_lowercase();
        anyhow::ensure!(
            actual == expected,
            "binary hash mismatch for '{}': expected {expected}, got {actual}",
            path.display()
        );
        tracing::info!(binary = %path.display(), "SHA-256 OK");
    }

    if let Some(bundle) = &cfg.cosign_bundle {
        run_cosign(
            &path.to_string_lossy(),
            bundle,
            cfg.cosign_identity.as_deref(),
            cfg.cosign_issuer.as_deref(),
        )
        .await?;
        tracing::info!(binary = %path.display(), "cosign bundle verified OK");
    }

    Ok(())
}

/// Compute the lowercase hex SHA-256 of a file.
/// Runs synchronously — call via `spawn_blocking`.
fn sha256_hex(path: &std::path::Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open '{}': {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Resolve `cmd` to an absolute path using PATH lookup when needed.
fn resolve_binary(cmd: &str) -> anyhow::Result<std::path::PathBuf> {
    let path = std::path::Path::new(cmd);
    if path.is_absolute() {
        anyhow::ensure!(path.exists(), "binary not found: {cmd}");
        return Ok(path.to_path_buf());
    }
    which::which(cmd).map_err(|_| anyhow::anyhow!("binary not found on PATH: {cmd}"))
}

/// Run `cosign verify-blob` as a subprocess.
/// Exits 0 → signature valid. Any other exit → error with captured stderr.
async fn run_cosign(
    binary: &str,
    bundle: &str,
    identity: Option<&str>,
    issuer: Option<&str>,
) -> anyhow::Result<()> {
    let cosign = which::which("cosign").map_err(|_| {
        anyhow::anyhow!(
            "cosign not found on PATH — install it from https://github.com/sigstore/cosign/releases"
        )
    })?;

    let mut cmd = tokio::process::Command::new(&cosign);
    cmd.args(["verify-blob", "--bundle", bundle, binary]);
    if let Some(id) = identity {
        cmd.args(["--certificate-identity", id]);
    }
    if let Some(iss) = issuer {
        cmd.args(["--certificate-oidc-issuer", iss]);
    }

    let out = cmd
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to run cosign '{}': {e}", cosign.display()))?;

    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(anyhow::anyhow!(
        "cosign verification failed for '{binary}': {stderr}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f
    }

    #[test]
    fn sha256_hex_known_value() {
        // echo -n "" | sha256sum → e3b0c44...
        let f = write_temp(b"");
        let hash = sha256_hex(f.path()).unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_non_empty() {
        // echo -n "hello" | sha256sum → 2cf24dba...
        let f = write_temp(b"hello");
        let hash = sha256_hex(f.path()).unwrap();
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[tokio::test]
    async fn correct_hash_passes() {
        let f = write_temp(b"hello");
        let cfg = BinaryVerifyConfig {
            sha256: Some(
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
            ),
            cosign_bundle: None,
            cosign_identity: None,
            cosign_issuer: None,
        };
        verify_binary(f.path().to_str().unwrap(), &cfg)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wrong_hash_fails() {
        let f = write_temp(b"hello");
        let cfg = BinaryVerifyConfig {
            sha256: Some("deadbeef".to_string()),
            cosign_bundle: None,
            cosign_identity: None,
            cosign_issuer: None,
        };
        let err = verify_binary(f.path().to_str().unwrap(), &cfg)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[tokio::test]
    async fn uppercase_hash_normalised() {
        let f = write_temp(b"hello");
        let cfg = BinaryVerifyConfig {
            sha256: Some(
                "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824".to_string(),
            ),
            cosign_bundle: None,
            cosign_identity: None,
            cosign_issuer: None,
        };
        verify_binary(f.path().to_str().unwrap(), &cfg)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn no_config_no_check() {
        let f = write_temp(b"anything");
        let cfg = BinaryVerifyConfig {
            sha256: None,
            cosign_bundle: None,
            cosign_identity: None,
            cosign_issuer: None,
        };
        // Should pass trivially — no checks configured
        verify_binary(f.path().to_str().unwrap(), &cfg)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_binary_fails() {
        let cfg = BinaryVerifyConfig {
            sha256: Some("abc".to_string()),
            cosign_bundle: None,
            cosign_identity: None,
            cosign_issuer: None,
        };
        let err = verify_binary("/nonexistent/binary", &cfg)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }
}
