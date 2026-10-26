//! Things the Explorer menu starts, integrity checks, repair and the administrator retry.

use super::jobs::{Job, Outcome};
use super::{AfterOpen, App, CreateDialog, FORMATS, ResultInfo, theme};
use crate::admin;
use crate::diag;
use crate::i18n::{Key, t, tf};
use packrat_core::extract::Resolution;
use packrat_core::verify::{self, VerifyReport};
use packrat_core::{OpenOptions, Progress};
use std::path::{Path, PathBuf};

fn item_base(p: &Path) -> String {
    let name = if p.is_dir() { p.file_name() } else { p.file_stem() };
    name.map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into())
}

/// `<folder>\<name>.<ext>` next to the first item, with `(2)`, `(3)`… when the name is taken.
pub fn default_output(items: &[PathBuf], ext: &str) -> PathBuf {
    let (base, parent) = match items.first() {
        Some(first) if items.len() == 1 => (
            item_base(first),
            first.parent().map(Path::to_path_buf).unwrap_or_default(),
        ),
        Some(first) => {
            let parent = first.parent().map(Path::to_path_buf).unwrap_or_default();
            let name = parent
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "archive".into());
            (name, parent)
        }
        None => ("archive".into(), PathBuf::new()),
    };
    let mut candidate = parent.join(format!("{base}.{ext}"));
    let mut n = 2;
    while candidate.exists() && n < 1000 {
        candidate = parent.join(format!("{base} ({n}).{ext}"));
        n += 1;
    }
    candidate
}

fn resolution_name(r: Resolution) -> &'static str {
    match r {
        Resolution::Skip => "skip",
        Resolution::Replace => "replace",
        Resolution::KeepBoth => "keep-both",
    }
}

impl App {
    /// "To .zip / .7z / .tar.zst" from the Explorer menu: no dialog, the archive appears next to the files.
    pub(super) fn quick_create(&mut self, ctx: &eframe::egui::Context, format: &str, items: Vec<PathBuf>) {
        let Some(idx) = FORMATS.iter().position(|(_, n)| *n == format) else {
            self.show_toast(tf(Key::ErrorGeneric, &[format]));
            return;
        };
        let ext = Self::format_from_index(idx).extension();
        let output = default_output(&items, ext);
        self.create = Some(CreateDialog {
            password: String::new(),
            encrypt_names: true,
            items,
            format: idx,
            level: self.settings.level.clamp(1, 9),
            // the quick actions of the Explorer menu never add recovery data on their own
            recovery: 0,
            output: output.to_string_lossy().into_owned(),
            output_edited: true,
        });
        self.start_create(ctx);
    }

    pub(super) fn start_verify(&mut self, ctx: &eframe::egui::Context) {
        let Some(l) = &self.loaded else { return };
        if l.has_encrypted() && l.opts.password.is_none() && l.path.is_some() {
            self.ask_password_for_open_archive();
            if let Some(d) = self.password_dialog.as_mut() {
                d.then = AfterOpen::Verify;
            }
            return;
        }
        let archive = l.archive.clone();
        let path = l.path.clone();
        let threads = self.threads();
        diag::info("integrity check started");
        self.job = Some(Job::spawn(ctx, t(Key::VerifyRunning).to_owned(), move |progress| {
            let started = std::time::Instant::now();
            let report = verify::verify(&*archive, None, threads, &progress);
            let files = report.ok + report.failures.len() as u64;
            let sha256 = path
                .as_ref()
                .and_then(|p| verify::sha256_file(p, &Progress::new()).ok());
            Outcome::Verified {
                report: Box::new(report),
                sha256,
                secs: started.elapsed().as_secs_f64(),
                files,
            }
        }));
    }

    pub(super) fn finish_verify(&mut self, report: VerifyReport, sha256: Option<String>, secs: f64, files: u64) {
        let _ = secs;
        diag::info(&format!(
            "integrity check finished: {} ok, {} damaged",
            report.ok,
            report.failures.len()
        ));
        let mut lines = Vec::new();
        if report.cancelled {
            lines.push(t(Key::Cancelled).to_owned());
        }
        if report.failures.is_empty() {
            lines.push(tf(
                Key::VerifyClean,
                &[&report.ok.to_string(), &theme::human_size(report.bytes)],
            ));
        } else {
            lines.push(tf(
                Key::VerifyDamaged,
                &[&report.failures.len().to_string(), &files.to_string()],
            ));
        }
        if let Some(h) = sha256 {
            lines.push(tf(Key::VerifySha, &[&h]));
        }
        let details = report
            .failures
            .iter()
            .map(|f| {
                if f.path.is_empty() {
                    format!("✖ {}", f.message)
                } else {
                    format!("✖ {} — {}", f.path, f.message)
                }
            })
            .collect();
        self.result = Some(ResultInfo {
            ok: report.is_clean(),
            lines,
            details,
            ..Default::default()
        });
    }

    /// Opens a ZIP whose structure is damaged by scanning its local headers, in repair mode.
    pub(super) fn repair_open(&mut self, ctx: &eframe::egui::Context, path: PathBuf) {
        self.repair_mode = true;
        self.open_path_with(ctx, path, OpenOptions::default().with_recover());
    }

    /// The archive on screen, reopened in repair mode.
    pub(super) fn repair_current(&mut self, ctx: &eframe::egui::Context) {
        let Some(l) = &self.loaded else { return };
        let mut opts = l.opts.clone();
        opts.recover = true;
        self.repair_mode = true;
        self.reopen_with(ctx, opts);
    }

    /// Runs inside the elevated process started by `retry_as_admin`.
    pub(super) fn start_elevated(&mut self, ctx: &eframe::egui::Context, job_file: &Path) {
        ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Title(
            t(Key::AdminWindowTitle).to_owned(),
        ));
        match admin::read_and_delete(job_file) {
            Err(e) => {
                diag::warn(&format!("elevated job refused: {e}"));
                self.result = Some(ResultInfo {
                    ok: false,
                    lines: vec![tf(Key::ErrorGeneric, &[&e])],
                    ..Default::default()
                });
            }
            Ok(job) => {
                diag::info("elevated extraction started");
                self.pending_names = job.entries;
                self.resolution_override = Some(match job.resolution.as_str() {
                    "replace" => Resolution::Replace,
                    "keep-both" => Resolution::KeepBoth,
                    _ => Resolution::Skip,
                });
                self.after_open = AfterOpen::Extract {
                    dest: job.dest,
                    smart: job.smart,
                    selected_only: false,
                };
                self.open_path(ctx, job.archive);
            }
        }
    }

    /// Repeats an extraction in a separate window with administrator rights (one UAC prompt).
    pub(super) fn retry_as_admin(&mut self, mut job: admin::Job) {
        job.resolution = resolution_name(self.resolution_override.unwrap_or_default()).into();
        let result = std::env::current_exe()
            .map_err(|e| e.to_string())
            .and_then(|exe| admin::write(&job).and_then(|file| admin::launch(&exe, &file)));
        match result {
            Ok(()) => diag::info("administrator window requested"),
            Err(e) => {
                diag::warn(&format!("administrator retry failed: {e}"));
                self.show_toast(tf(Key::ErrorGeneric, &[&e]));
            }
        }
    }
}
