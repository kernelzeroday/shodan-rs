use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

fn config_dir_from(home: &Path) -> PathBuf {
    let legacy = home.join(".shodan");
    if legacy.exists() {
        legacy
    } else {
        home.join(".config").join("shodan")
    }
}

fn config_dir() -> PathBuf {
    let home = dirs::home_dir().expect("Cannot determine home directory");
    config_dir_from(&home)
}

pub fn load_api_key() -> Result<String> {
    load_api_key_from(&config_dir())
}

pub fn save_api_key(key: &str) -> Result<()> {
    save_api_key_to(key, &config_dir())
}

fn load_api_key_from(dir: &Path) -> Result<String> {
    let path = dir.join("api_key");
    if !path.exists() {
        anyhow::bail!(
            r#"Please run "shodan-rs init <api key>" before using this command"#
        );
    }
    let meta = fs::metadata(&path)?;
    if meta.permissions().mode() & 0o777 != 0o600 {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    let key = fs::read_to_string(&path).context("Failed to read API key file")?;
    Ok(key.trim().to_string())
}

fn save_api_key_to(key: &str, dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("Failed to create config directory")?;
    let path = dir.join("api_key");
    fs::write(&path, key).context("Failed to write API key")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_api_key() {
        let tmp = TempDir::new().unwrap();
        let dir = config_dir_from(tmp.path());
        save_api_key_to("my-test-key-123", &dir).unwrap();
        let key = load_api_key_from(&dir).unwrap();
        assert_eq!(key, "my-test-key-123");
    }

    #[test]
    fn test_load_missing_key_errors() {
        let tmp = TempDir::new().unwrap();
        let dir = config_dir_from(tmp.path());
        let result = load_api_key_from(&dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("shodan-rs init"));
    }

    #[test]
    fn test_key_file_permissions() {
        let tmp = TempDir::new().unwrap();
        let dir = config_dir_from(tmp.path());
        save_api_key_to("test-key", &dir).unwrap();
        let meta = fs::metadata(dir.join("api_key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn test_legacy_dir_preferred() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join(".shodan")).unwrap();
        let dir = config_dir_from(tmp.path());
        assert!(dir.ends_with(".shodan"));
    }

    #[test]
    fn test_xdg_dir_used_when_no_legacy() {
        let tmp = TempDir::new().unwrap();
        let dir = config_dir_from(tmp.path());
        assert!(dir.ends_with("shodan"));
        assert!(dir.to_str().unwrap().contains(".config"));
    }
}
