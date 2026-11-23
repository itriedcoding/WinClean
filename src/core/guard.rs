//! Safety rules that every destructive operation must pass through.
//!
//! Three layers protect the machine:
//! 1. Protected Windows/system locations can never be deleted, whatever the caller asks.
//! 2. Personal folders (documents, pictures, desktop, downloads, ...) are only ever
//!    touched when the user explicitly reviewed and approved those exact items.
//! 3. Only paths inside a scan target root accepted by this run are deletable.

use crate::core::paths;
use crate::model::Category;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Normalises a path for comparison: lowercase, backslashes, no trailing slash.
pub fn normalize(path: &Path) -> String {
    let mut raw = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    while raw.contains("\\\\") {
        raw = raw.replace("\\\\", "\\");
    }
    let mut trimmed = raw.trim_end_matches('\\').to_string();
    if trimmed.len() == 2 && trimmed.ends_with(':') {
        trimmed.push('\\');
    }
    trimmed
}

/// True when `path` is inside (or equal to) `root`.
pub fn is_within(path: &str, root: &str) -> bool {
    if path == root {
        return true;
    }
    let root_with_sep = if root.ends_with('\\') {
        root.to_string()
    } else {
        format!("{root}\\")
    };
    path.starts_with(&root_with_sep)
}

fn protected_roots() -> &'static Vec<String> {
    static ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let win = paths::windows_dir();
        let program_files = paths::program_files();
        let program_files_x86 = paths::program_files_x86();
        let program_data = paths::program_data();
        let system_drive = paths::system_drive();
        let mut roots: Vec<PathBuf> = vec![
            win.join("System32"),
            win.join("SysWOW64"),
            win.join("WinSxS"),
            win.join("servicing"),
            win.join("assembly"),
            win.join("Boot"),
            win.join("Fonts"),
            win.join("SystemResources"),
            win.join("diagnostics"),
            win.join("SystemApps"),
            program_files.join("WindowsApps"),
            program_files.join("Windows Defender"),
            program_files_x86.join("Windows Defender"),
            program_data.join("Microsoft\\Windows Defender"),
            program_data.join("Microsoft\\Windows\\SystemData"),
            PathBuf::from(r"C:\$Recycle.Bin"),
            PathBuf::from(r"C:\Recovery"),
            PathBuf::from(r"C:\EFI"),
            PathBuf::from(r"C:\Boot"),
            PathBuf::from(r"C:\System Volume Information"),
            PathBuf::from(r"C:\Windows.old"),
        ];
        roots.push(system_drive.join("Boot"));
        roots.push(system_drive.join("Recovery"));
        roots.push(system_drive.join("System Volume Information"));
        roots.push(system_drive.join("$Recycle.Bin"));
        roots.iter().map(|p| normalize(p)).collect()
    })
}

/// Absolute paths that must never be deleted even if they sit in a temp root.
fn protected_files() -> &'static Vec<String> {
    static FILES: OnceLock<Vec<String>> = OnceLock::new();
    FILES.get_or_init(|| {
        let win = paths::windows_dir();
        let system_drive = paths::system_drive();
        [
            win.join("explorer.exe"),
            win.join("notepad.exe"),
            win.join("regedit.exe"),
            system_drive.join("pagefile.sys"),
            system_drive.join("hiberfil.sys"),
            system_drive.join("swapfile.sys"),
            system_drive.join("DumpStack.log.tmp"),
            system_drive.join("bootmgr"),
            paths::user_profile().join("NTUSER.DAT"),
        ]
        .iter()
        .map(|p| normalize(p))
        .collect()
    })
}

/// Files and folders that the recursive walker must never descend into.
pub fn skip_directory_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "system volume information"
            | "$recycle.bin"
            | "winsxs"
            | "system32"
            | "syswow64"
            | "servicing"
            | "assembly"
            | "config.msi"
            | "recovery"
            | "windowsapps"
            | "windows defender"
            | "$windows.~bt"
            | "$windows.~ws"
            | "$sysreset"
    )
}

/// True when this path belongs to protected Windows/system infrastructure.
pub fn is_protected(path: &Path) -> bool {
    let normalized = normalize(path);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(
        file_name.as_str(),
        "ntuser.dat"
            | "ntuser.ini"
            | "pagefile.sys"
            | "hiberfil.sys"
            | "swapfile.sys"
            | "bootmgr"
            | "bcd"
    ) {
        return true;
    }
    if protected_files().iter().any(|p| *p == normalized) {
        return true;
    }
    protected_roots()
        .iter()
        .any(|root| is_within(&normalized, root))
}

fn env_dir(profile: &Path, name: &str) -> String {
    normalize(&profile.join(name))
}

/// User folders that hold personal data. Never cleaned without explicit approval.
pub fn is_personal(path: &Path) -> bool {
    let normalized = normalize(path);
    let profile = paths::user_profile();
    let personal = [
        env_dir(&profile, "Documents"),
        env_dir(&profile, "Desktop"),
        env_dir(&profile, "Downloads"),
        env_dir(&profile, "Pictures"),
        env_dir(&profile, "Videos"),
        env_dir(&profile, "Music"),
        env_dir(&profile, "OneDrive"),
        env_dir(&profile, "Favorites"),
        env_dir(&profile, "Contacts"),
        env_dir(&profile, "Links"),
        env_dir(&profile, "Saved Games"),
        env_dir(&profile, "Searches"),
        normalize(&paths::roaming_appdata().join("Microsoft\\Windows\\Start Menu")),
    ];
    personal.iter().any(|root| is_within(&normalized, root))
}

/// Expands and lowercases every exclusion rule once so per-file checks stay cheap.
pub fn prepare_exclusions(rules: &[String]) -> Vec<String> {
    rules
        .iter()
        .map(|rule| paths::expand_env(rule.trim()))
        .filter(|rule| !rule.is_empty())
        .map(|rule| {
            if rule.contains('/') {
                rule.replace('/', "\\")
            } else {
                rule
            }
            .to_ascii_lowercase()
        })
        .collect()
}

/// True when the path matches any exclusion rule (prefix or wildcard pattern).
pub fn is_excluded(path: &Path, prepared_rules: &[String]) -> bool {
    if prepared_rules.is_empty() {
        return false;
    }
    let normalized = normalize(path);
    prepared_rules.iter().any(|rule| {
        let rule = rule.trim_end_matches('\\');
        if rule.contains('*') || rule.contains('?') {
            glob_match(rule, &normalized)
        } else {
            is_within(&normalized, rule) || normalized == rule
        }
    })
}

/// Case insensitive wildcard matcher supporting `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Why a deletion request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    ProtectedSystemPath,
    PersonalData,
    Excluded,
    OutsideScanRoots,
    UnsafeEntry,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::ProtectedSystemPath => {
                "Protected Windows system location — never deleted by WinClean"
            }
            Refusal::PersonalData => "Personal folder — requires explicit per-item approval",
            Refusal::Excluded => "Matches an exclusion rule in Settings",
            Refusal::OutsideScanRoots => "Outside the scanned cleanup locations",
            Refusal::UnsafeEntry => "Symbolic link or reparse point — skipped for safety",
        }
    }
}

/// Decides whether one finding may be deleted.
pub struct DeletePolicy<'a> {
    pub allowed_roots: &'a [PathBuf],
    pub exclusions: &'a [String],
    pub allow_personal: bool,
}

impl<'a> DeletePolicy<'a> {
    pub fn evaluate(&self, path: &Path, category: Category) -> Result<(), Refusal> {
        let normalized = normalize(path);

        if is_protected(path) {
            return Err(Refusal::ProtectedSystemPath);
        }
        if is_excluded(path, self.exclusions) {
            return Err(Refusal::Excluded);
        }
        if is_personal(path) && !(self.allow_personal && category == Category::LargeFile) {
            return Err(Refusal::PersonalData);
        }
        if category == Category::LargeFile && !self.allow_personal {
            return Err(Refusal::PersonalData);
        }
        if category == Category::Duplicate && is_personal(path) && !self.allow_personal {
            return Err(Refusal::PersonalData);
        }

        let inside_root = self.allowed_roots.iter().any(|root| {
            let root_norm = normalize(root);
            is_within(&normalized, &root_norm)
        });
        if !inside_root && category != Category::RecycleBin {
            return Err(Refusal::OutsideScanRoots);
        }

        // Never follow a link: deleting through a junction could escape any guard.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta_is_link(&meta) {
                return Err(Refusal::UnsafeEntry);
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
fn meta_is_link(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn meta_is_link(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching_works() {
        assert!(glob_match(r"c:\temp\*", r"c:\temp\a.tmp"));
        assert!(glob_match("*.log", r"c:\x\a.log"));
        assert!(glob_match(r"c:\?\a.tmp", r"c:\x\a.tmp"));
        assert!(!glob_match(r"c:\temp\*", r"c:\other\a.tmp"));
        assert!(!glob_match(r"*.log", r"a.txt"));
        assert!(glob_match("abc*", "abcdef"));
    }

    #[test]
    fn path_containment_is_segment_aware() {
        assert!(is_within(r"c:\temp\a", r"c:\temp"));
        assert!(is_within(r"c:\temp", r"c:\temp"));
        assert!(!is_within(r"c:\tempest\a", r"c:\temp"));
        assert!(is_within(
            &normalize(Path::new(r"c:\\temp\\a")),
            &normalize(Path::new(r"c:\\temp"))
        ));
    }

    #[test]
    fn protects_system_locations() {
        assert!(is_protected(Path::new(
            r"C:\Windows\System32\drivers\etc\hosts"
        )));
        assert!(is_protected(Path::new(r"C:\Windows\WinSxS\foo.dll")));
        assert!(is_protected(Path::new(r"C:\pagefile.sys")));
        assert!(!is_protected(Path::new(r"C:\Windows\Temp\a.tmp")));
    }

    #[test]
    fn detects_personal_folders() {
        let profile = paths::user_profile();
        assert!(is_personal(&profile.join("Documents\\tax.pdf")));
        assert!(is_personal(&profile.join("Pictures\\holiday.jpg")));
        assert!(!is_personal(&paths::local_appdata().join("Temp\\a.tmp")));
    }

    #[test]
    fn exclusions_match_prefix_and_wildcards() {
        let rules =
            prepare_exclusions(&[r"C:\Windows\Temp\Keep".into(), r"*\important.log".into()]);
        assert!(is_excluded(
            Path::new(r"C:\Windows\Temp\Keep\x.tmp"),
            &rules
        ));
        assert!(is_excluded(
            Path::new(r"C:\Windows\Temp\important.log"),
            &rules
        ));
        assert!(!is_excluded(Path::new(r"C:\Windows\Temp\a.tmp"), &rules));
    }

    #[test]
    fn policy_refuses_outside_roots() {
        let roots = vec![PathBuf::from(r"C:\Windows\Temp")];
        let rules = prepare_exclusions(&[]);
        let policy = DeletePolicy {
            allowed_roots: &roots,
            exclusions: &rules,
            allow_personal: true,
        };
        assert_eq!(
            policy.evaluate(Path::new(r"C:\Windows\Temp\a.tmp"), Category::WindowsTemp),
            Ok(())
        );
        let personal = paths::user_profile().join("Documents").join("x.txt");
        assert_eq!(
            policy.evaluate(&personal, Category::UserTemp),
            Err(Refusal::PersonalData)
        );
        assert_eq!(
            policy.evaluate(
                Path::new(r"C:\Windows\System32\a.dll"),
                Category::WindowsTemp
            ),
            Err(Refusal::ProtectedSystemPath)
        );
    }
}
