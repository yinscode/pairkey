//! Optional operator configuration, read once and passed separately to both workers.
use super::*;
use pairkey_sdk::approval::{validate_oidc_issuers, IssuerConfig};
pub(crate) fn load(path: &Path) -> Result<Vec<IssuerConfig>> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let metadata = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        other => other?,
    };
    ensure!(
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o077 == 0,
        "OIDC settings must be a private regular file"
    );
    let mut bytes = vec![];
    std::fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "OIDC settings too large");
    let configs = serde_json::from_slice::<Vec<IssuerConfig>>(&bytes)?;
    validate_oidc_issuers(&configs)?;
    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_is_disabled_and_config_errors_are_not_silently_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("pairkey-oidc-config-{}", hex(&fresh())));
        assert!(load(&path).unwrap().is_empty());
        let valid = json!([{"issuer":"https://issuer.example","audience":"pairkey-test","jwks_url":"https://issuer.example/keys"}]);
        private(&path, &serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(load(&path).unwrap().len(), 1);
        let mut invalid = valid.clone();
        invalid[0]["jwks_url"] = json!("http://issuer.example/keys");
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(load(&path).is_err());
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
