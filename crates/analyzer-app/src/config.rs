use crate::core::ai::{self, AiConfig};
use anyhow::{Context, Result};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub struct ConfigService;
impl ConfigService {
    pub fn default_path() -> PathBuf {
        ai::default_config_path()
    }
    pub fn load(path: &Path) -> Result<AiConfig> {
        AiConfig::load(path)
    }
    pub fn create(path: &Path) -> Result<()> {
        ai::init_config(path)
    }
    pub fn check(config: &AiConfig) -> Result<()> {
        ai::check(config)
    }
    /// Explicit settings save: validate before replacing, keep a failed write from
    /// truncating the previous configuration. NamedTempFile uses 0600 on Unix.
    pub fn save(path: &Path, config: &AiConfig) -> Result<()> {
        config.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temporary.write_all(toml::to_string_pretty(config)?.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|e| e.error)
            .context("无法保存 AI 配置")?;
        Ok(())
    }
    pub fn redacted(config: &AiConfig) -> Result<String> {
        let mut visible = config.clone();
        if !visible.api_key.is_empty() {
            visible.api_key = "[已配置，密钥已隐藏]".into();
        }
        if visible.api_key_env.starts_with("sk-") {
            visible.api_key_env = "[密钥已隐藏，请改用 api_key]".into();
        }
        Ok(serde_json::to_string_pretty(&visible)?)
    }
}
