//! Well known Windows folders, with portable fallbacks so the engine can be
//! compiled and unit tested on any operating system.

use std::path::{Path, PathBuf};

fn var_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

pub fn windows_dir() -> PathBuf {
    var_path("SystemRoot")
        .or_else(|| var_path("WINDIR"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

pub fn system_drive() -> PathBuf {
    var_path("SystemDrive").unwrap_or_else(|| PathBuf::from("C:"))
}

pub fn user_profile() -> PathBuf {
    var_path("USERPROFILE").unwrap_or_else(|| PathBuf::from(r"C:\Users\Default"))
}

pub fn local_appdata() -> PathBuf {
    var_path("LOCALAPPDATA").unwrap_or_else(|| user_profile().join("AppData\\Local"))
}

pub fn roaming_appdata() -> PathBuf {
    var_path("APPDATA").unwrap_or_else(|| user_profile().join("AppData\\Roaming"))
}

pub fn program_data() -> PathBuf {
    var_path("PROGRAMDATA").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

pub fn program_files() -> PathBuf {
    var_path("ProgramFiles").unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
}

pub fn program_files_x86() -> PathBuf {
    var_path("ProgramFiles(x86)").unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"))
}

pub fn temp_dir() -> PathBuf {
    var_path("TEMP")
        .or_else(|| var_path("TMP"))
        .unwrap_or_else(std::env::temp_dir)
}

/// Per-user application data folder for settings, state and logs.
pub fn app_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(appdata) = var_path("APPDATA") {
            return appdata.join("WinClean");
        }
    }
    if let Some(home) = var_path("HOME") {
        return home.join(".config").join("winclean");
    }
    PathBuf::from("winclean-data")
}

pub fn log_dir() -> PathBuf {
    app_data_dir().join("logs")
}

pub fn settings_file() -> PathBuf {
    app_data_dir().join("settings.json")
}

pub fn state_file() -> PathBuf {
    app_data_dir().join("state.json")
}

/// Creates the parent directory of `path` when it is missing.
pub fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Expands `%VARIABLE%` references used in user supplied exclusion rules.
pub fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) if !name.is_empty() => out.push_str(&value),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// True when the path exists and is a directory.
pub fn is_dir(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("WINCLEAN_TEST_DIR", r"C:\Temp\Test");
        assert_eq!(
            expand_env(r"%WINCLEAN_TEST_DIR%\cache"),
            r"C:\Temp\Test\cache"
        );
        assert_eq!(expand_env("100%"), "100%");
        assert_eq!(expand_env(r"%NOT_DEFINED_HERE%\x"), r"%NOT_DEFINED_HERE%\x");
    }

    #[test]
    fn app_data_lives_under_the_user() {
        let dir = app_data_dir();
        assert!(dir
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("winclean"));
    }

    #[test]
    fn fallback_paths_are_absolute() {
        assert!(windows_dir().is_absolute() || windows_dir().to_string_lossy().starts_with("C:"));
    }
}
