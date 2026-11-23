# WinClean

**A lightweight Windows PC cleaner and security dashboard — written entirely in Rust.**

WinClean is a native Windows desktop application for reclaiming disk space, understanding what is
using your drive, and checking your machine's security posture through Microsoft Defender. It is a
single, self-contained `.exe`: no installer, no background service, no telemetry, no network
calls, and no bundled browser engine.

![Rust](https://img.shields.io/badge/Rust-1.80%2B-000?logo=rust)
![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Why WinClean

Most "PC optimisers" are heavy Electron apps that run always-on services, nag you to buy a
subscription, and delete files aggressively. WinClean takes the opposite approach:

- **Native and small.** Rust + [`egui`](https://github.com/emilk/egui) painted with OpenGL. The
  release profile uses `opt-level = "s"`, LTO, `panic = "abort"` and symbol stripping.
- **Idle-friendly.** No background threads when nothing is running. The process list refreshes on
  a page-aware cadence (0.5–4 s) and stops repainting when the window is not visible.
- **Review-first.** Nothing is deleted without a confirmation dialog showing exactly what will go,
  how many files and how many bytes. Personal folders need a second, explicit approval.
- **No fake results.** Scans stream real filesystem entries. Defender results come from Defender
  itself, and removals are re-verified against `Get-MpThreat` before the UI reports success.
- **No "security theatre".** WinClean never disables Defender, the firewall, SmartScreen or any
  other Windows protection, and never asks you to.

---

## Features

### Dashboard
System health score with the checks behind it, low-storage banner, Defender status, recent
activity, total bytes freed, and one-click routes to the most useful actions.

### Quick Clean
The everyday cleanup: Windows and user temp files, browser caches, thumbnail/icon caches, crash
dumps, error reports, Windows Update download cache and Delivery Optimization data. Every category
is reviewed, filterable and individually selectable before deletion.

### Deep Clean
Everything from Quick Clean plus a full-disk sweep for orphaned logs and leftovers, Recycle Bin
contents, and — if you explicitly enable it — Prefetch data (off by default, because launch traces
help startup performance). Deep Clean can scan every fixed drive or a single volume.

### Large Files
Lists files above a configurable threshold (1 GB by default) with full path, size, last-modified
date and containing folder. Sortable and filterable. Large files are **never** preselected and are
**never** deleted automatically, regardless of size.

### Malware Scanner
- Runs Microsoft Defender quick, full or custom-folder scans through the installed Defender engine.
- Live progress; cancellation stops the scan instead of hiding it.
- Threat list with name, severity, classification and recommended action, sourced from
  `Get-MpThreat` / `Get-MpThreatDetection`.
- Remediation is performed by Defender and then re-queried; WinClean only claims a threat is gone
  when Defender reports it inactive. Suspicious files are never executed.
- Local heuristics flag risky startup entries and processes (temp-folder launches, impersonated
  Windows binaries, encoded PowerShell) as a reason to look closer — never as a malware verdict.
- Signature updates and a shortcut to Windows Security.

### Storage Analyzer
Per-volume usage breakdown, largest folders (async folder-size scan), installed applications by
size, Recycle Bin size, and a ranked list of recommendations with the bytes each could free.

When free space drops below the configurable threshold (**100 GB by default**), the dashboard and
this page show a prominent warning with a guided cleanup path. Recommendations are suggestions; the
user still reviews and confirms each deletion.

### Startup Manager
Enumerates Run/RunOnce entries from HKCU and HKLM (32- and 64-bit views), the user and common
Startup folders, and scheduled tasks (read-only). Entries can be disabled and re-enabled using the
same `StartupApproved` registry values Windows Task Manager uses, so toggles are reversible and
survive reboots.

### System Monitor
Live CPU, memory, process count and uptime, a 90-sample CPU/memory history chart, and a sortable
process table with image path, CPU, working set and an "end task" action behind a confirmation.

### Settings
Dark and light themes, reduced motion, monitor cadence, large-file and duplicate thresholds,
low-storage threshold, Prefetch and system-folder scan toggles, exclusion rules, autostart,
weekly maintenance, elevation, and the full operation log.

---

## Safety model

WinClean is deliberately conservative. Deletion passes through three independent layers:

1. **Path guard** (`src/core/guard.rs`)
   - Always-protected roots: `System32`, `SysWOW64`, `WinSxS`, `WindowsApps`, `Recovery`,
     `Boot`, `System Volume Information`, driver stores and the Defender platform directory.
   - Reparse points and symlinks are refused, so a link cannot redirect a delete outside the scan.
   - Personal folders (Documents, Desktop, Pictures, Videos, Music, Downloads, OneDrive) require
     `approve_personal`, set only after the user ticks the second confirmation.
2. **Allowed roots** — a deletion must be inside the roots that produced the finding. Large-file
   and duplicate deletion uses volume roots; cleanup uses temp/cache roots.
3. **Confirmation dialog** — per-run approval showing item count and total size, with exclusions
   applied before the job starts.

Other guarantees:

- Read-only attributes are cleared before deletion, but no ACLs or ownership are changed.
- Locked or in-use files are skipped and reported; nothing is force-deleted.
- Exclusions accept prefixes, `?`/`*` wildcards and `%VARIABLES%`.
- Every scan, clean, startup toggle, Defender action and error is appended to a local log at
  `%APPDATA%\WinClean\logs\winclean.log`.
- No file contents are uploaded anywhere. There is no networking code in the application.

### Elevation

The app starts as a standard user. Windows-protected paths (for example `C:\Windows\Temp` and the
Windows Update cache) require administrator rights; the UI says so and offers an on-demand restart
through the standard UAC prompt. Everything user-scoped works without elevation.

---

## Install

1. Download `winclean.exe` from the [latest release](../../releases/latest).
2. Put it anywhere you like and run it. No installer, no runtime, no Rust toolchain required.
3. Optionally tick **Start WinClean with Windows** or **Weekly maintenance** in Settings.

Windows SmartScreen may warn about a new unsigned executable. Choose **More info → Run anyway**, or
build it yourself from source (below). The release binary is unsigned because code-signing
certificates are user-specific.

### Requirements

- Windows 10 (1809+) or Windows 11, x64.
- Microsoft Defender is used when present. A third-party antivirus that disables Defender's
  PowerShell interface simply means the Defender panels report unavailable; cleaning still works.
- OpenGL 3.3+ capable drivers (any Windows 10/11 machine with a current GPU driver).

---

## Build from source

```powershell
git clone https://github.com/itriedcoding/WinClean.git
cd WinClean
cargo build --release
# -> target\release\winclean.exe
```

Requirements: Rust stable (1.80 or newer), the MSVC toolchain, and the Windows 10/11 SDK.

Run the tests:

```powershell
cargo test
```

Cross-check the Windows integration from Linux/macOS (type checking only):

```bash
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu --all-targets
```

### Command line

```
winclean                 # start the desktop interface
winclean --maintenance   # headless safe cleanup (used by the weekly task)
winclean --version
winclean --help
```

`--maintenance` is intentionally narrower than Deep Clean: it only removes default-selected
cleanup categories, never touches personal folders, the Recycle Bin, large files or duplicates,
and returns a non-zero exit code if anything failed.

---

## Project layout

```
src/
  main.rs              entry point, runtime icon, CLI and headless maintenance
  app.rs               application state, navigation, job polling, dialogs
  theme.rs             dark/light palettes, Segoe UI loading, spacing
  model.rs             shared data types (findings, threats, volumes, …)
  format.rs            byte/date/duration formatting helpers
  settings.rs          persisted settings and application state
  core/                platform-independent engine
    scanner.rs         cancellable multi-root scanner with progress streaming
    clean.rs           deletion engine with per-item results
    guard.rs           protected paths, exclusions, personal-folder policy
    duplicates.rs      size-grouped BLAKE3 duplicate detection
    storage.rs         volume analytics, recommendations, health checks
    security.rs        threat classification and local heuristics
    logbook.rs         append-only operation log
    paths.rs           known folders and environment expansion
  platform/
    windows/           Defender (PowerShell/CIM), registry, processes, volume
                       enumeration, StartupApproved toggles, scheduled tasks,
                       ShellExecute helpers
    fallback.rs        portable stubs so the engine builds and tests on any OS
  ui/
    jobs.rs            background job wrappers (scan, clean, Defender, status)
    cleaner.rs         Quick/Deep/Large Files pages
    dashboard.rs       health overview
    malware.rs         Defender and heuristic results
    storage_page.rs    storage analyzer
    startup.rs         startup manager
    monitor.rs         live system monitor
    settings_page.rs   preferences, exclusions, logs
    widgets.rs         cards, badges, progress, dialogs, tables
    icons.rs           vector icons drawn with the painter (no image assets)
```

---

## Architecture notes

- **Streaming scans.** Workers walk the filesystem and send `Findings`/`Progress` batches over an
  `mpsc` channel. The UI polls once per frame, so a scan never blocks a click.
- **Cancellation** is an `AtomicBool` checked between directory entries and inside long loops.
- **No UI freezes.** Defender calls, registry enumeration, volume queries and folder sizing all run
  on short-lived worker threads.
- **Portable engine.** Core logic compiles and is unit-tested on Linux; Windows-specific behaviour
  is isolated under `src/platform/windows/`.
- **No third-party services.** No analytics, crash reporting, updater or ad network.

### Permissions used

- Standard user: scan/clean user temp and caches, read HKCU startup entries, enumerate processes,
  query Defender status, open Explorer/Settings.
- Administrator (on demand): clean Windows temp/update/logs, toggle HKLM startup entries, run
  remediation for machine-wide threats, install the weekly scheduled task.

WinClean never modifies protected system files, never disables security features, and never
elevates silently.

---

## Continuous integration and releases

`.github/workflows/build.yml` runs on every push to `main` and on manual dispatch:

1. `cargo test` on `windows-latest`.
2. `cargo build --release --locked` with the optimised profile.
3. Uploads `winclean.exe` as a build artifact.
4. Creates or updates the GitHub Release tagged `v<version from Cargo.toml>` and attaches the
   executable, with generated release notes.

To cut a release, bump `version` in `Cargo.toml`, commit, and push to `main`.

---

## Screenshots

The interface is drawn natively and is not reproducible outside a Windows session, so this
repository does not ship fabricated mock-ups. After running the application on Windows you can add
real captures to `docs/screenshots/` and embed them here:

| Page | What to capture |
| --- | --- |
| Dashboard | health ring, low-storage banner, Defender card |
| Quick Clean | results table with categories and the confirmation dialog |
| Large Files | sorted list with sizes and dates |
| Malware Scanner | scan progress and a threat row with severity |
| Storage Analyzer | volume bars and recommendations |
| Startup Manager | enabled/disabled entries and suspicious badge |
| System Monitor | CPU/memory history chart and process table |
| Settings | themes, exclusions and activity log |

---

## Known limitations

- Defender integration requires PowerShell and the Defender platform to be present and responsive.
  Controlled Folder Access or third-party AV can block it; the UI reports the error instead of
  pretending a scan ran.
- Scheduled tasks can be listed and opened in Task Scheduler, but are not toggled from WinClean;
  Windows does not expose a supported reversible switch equivalent to `StartupApproved`.
- Code signing is not configured. Add a certificate and a signing step to the workflow if you
  distribute the binary publicly.
- The application has been compiled and unit-tested, and the Windows target is type-checked in CI,
  but interactive QA on physical Windows 10/11 machines belongs to the release process. See
  [Testing](#testing) below.

## Testing

```powershell
cargo test                 # unit tests for the engine, settings and formatting
cargo clippy --all-targets # optional lint pass
```

The test suite covers path guarding, duplicate detection, exclusion matching, scan summaries,
settings migration, formatting and health scoring. Anything requiring Defender or elevation is
exercised manually on Windows.

## License

MIT — see [LICENSE](LICENSE).

WinClean is an independent utility. It is not affiliated with Microsoft. Microsoft Defender and
Windows are trademarks of Microsoft Corporation.
