use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// `%APPDATA%\Packrat` (or `PACKRAT_DATA_DIR`, which tests and portable setups can use).
pub fn data_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(d) = PRIVATE_DATA_DIR.with(|p| p.borrow().clone()) {
        return d;
    }
    if let Some(d) = std::env::var_os("PACKRAT_DATA_DIR") {
        return PathBuf::from(d);
    }
    std::env::var_os("APPDATA")
        .map(|a| PathBuf::from(a).join("Packrat"))
        .unwrap_or_else(|| std::env::temp_dir().join("Packrat"))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// "ru" or "en".
    pub language: String,
    /// Worker threads for compression and extraction; 0 = all cores.
    pub threads: usize,
    /// Extract with Smart Extract by default.
    pub smart_default: bool,
    /// Ask GitHub once a day whether a newer version exists.
    pub check_updates: bool,
    /// Unix seconds of the last update check.
    pub last_update_check: i64,
    pub recent: Vec<String>,
    /// Format name accepted by `Format::from_name`.
    pub default_format: String,
    pub level: u32,
    /// Recovery data percentage last used in the create dialog.
    pub recovery: u32,
    pub last_dest: Option<String>,
    /// Open the folder when an extraction ends cleanly.
    pub open_after_extract: bool,
    /// Move the archive to the Recycle Bin after a clean extraction of all of it.
    pub delete_after_extract: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "ru".into(),
            threads: 0,
            smart_default: true,
            check_updates: true,
            last_update_check: 0,
            recent: Vec::new(),
            default_format: "zip".into(),
            level: 6,
            recovery: 0,
            last_dest: None,
            open_after_extract: true,
            delete_after_extract: false,
        }
    }
}

impl Settings {
    fn path() -> PathBuf {
        data_dir().join("settings.json")
    }

    pub fn load() -> Self {
        std::fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let _ = std::fs::create_dir_all(data_dir());
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(Self::path(), json);
        }
    }

    pub fn remember(&mut self, archive: &str) {
        self.recent.retain(|r| !r.eq_ignore_ascii_case(archive));
        self.recent.insert(0, archive.to_owned());
        self.recent.truncate(10);
    }
}

#[cfg(test)]
thread_local! {
    static PRIVATE_DATA_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Gives the calling test thread a data folder of its own, for tests that change and save settings.
#[cfg(test)]
pub fn use_private_test_data_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    PRIVATE_DATA_DIR.with(|p| *p.borrow_mut() = Some(dir.path().to_path_buf()));
    dir
}

/// Points `PACKRAT_DATA_DIR` at one temp folder shared by all tests of this binary.
#[cfg(test)]
pub fn use_test_data_dir() -> PathBuf {
    use std::sync::OnceLock;
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    let dir = DIR.get_or_init(|| tempfile::tempdir().expect("temp dir"));
    // SAFETY: set before any test reads it and always to the same value.
    unsafe { std::env::set_var("PACKRAT_DATA_DIR", dir.path()) };
    dir.path().to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let s: Settings = serde_json::from_str(r#"{"language":"en","threads":3}"#).unwrap();
        assert_eq!(s.language, "en");
        assert_eq!(s.threads, 3);
        assert!(s.smart_default && s.check_updates);
    }

    #[test]
    fn recent_list_is_deduplicated_and_capped() {
        let mut s = Settings::default();
        for i in 0..15 {
            s.remember(&format!("C:\\a\\{i}.zip"));
        }
        s.remember("c:\\a\\3.ZIP");
        assert_eq!(s.recent.len(), 10);
        assert_eq!(s.recent[0], "c:\\a\\3.ZIP");
        assert_eq!(
            s.recent
                .iter()
                .filter(|r| r.eq_ignore_ascii_case("c:\\a\\3.zip"))
                .count(),
            1
        );
    }
}
