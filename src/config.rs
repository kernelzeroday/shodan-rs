use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};

fn config_dir() -> PathBuf {
    let home = dirs::home_dir().expect("Cannot determine home directory");
    let legacy = home.join(".shodan");
    if legacy.exists() {
        legacy
    } else {
        home.join(".config").join("shodan")
    }
}

pub fn api_key_path() -> PathBuf {
    config_dir().join("api_key")
}

pub fn load_api_key() -> Result<String> {
    let path = api_key_path();
    if !path.exists() {
        anyhow::bail!(
            r#"Please run "shodan init <api key>" before using this command"#
        );
    }
    // Enforce read-only permissions
    let meta = fs::metadata(&path)?;
    if meta.permissions().mode() & 0o777 != 0o600 {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    let key = fs::read_to_string(&path)
        .context("Failed to read API key file")?;
    Ok(key.trim().to_string())
}

pub fn save_api_key(key: &str) -> Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir).context("Failed to create config directory")?;
    let path = api_key_path();
    fs::write(&path, key).context("Failed to write API key")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    fn with_temp_home<F: FnOnce()>(f: F) -> TempDir {
        let tmp = TempDir::new().unwrap();
        // Safety: single-threaded test context; no concurrent env reads
        unsafe { env::set_var("HOME", tmp.path()) };
        f();
        tmp
    }

    #[test]
    fn test_save_and_load_api_key() {
        let _tmp = with_temp_home(|| {
            save_api_key("my-test-key-123").unwrap();
            let key = load_api_key().unwrap();
            assert_eq!(key, "my-test-key-123");
        });
    }

    #[test]
    fn test_load_missing_key_errors() {
        let _tmp = with_temp_home(|| {
            let result = load_api_key();
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("shodan init"));
        });
    }

    #[test]
    fn test_key_file_permissions() {
        let _tmp = with_temp_home(|| {
            save_api_key("test-key").unwrap();
            let meta = fs::metadata(api_key_path()).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        });
    }
}
