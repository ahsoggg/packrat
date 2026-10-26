//! The main window.

mod actions;
mod dialogs;
mod jobs;
mod preview;
mod queue;
mod secure;
mod shots;
pub mod theme;
mod tree;
mod views;

use crate::i18n::{self, Key, t, tf};
use crate::settings::Settings;
use crate::{diag, update};
use eframe::egui::{self, Ui};
use jobs::{Job, Loaded, Outcome};
use packrat_core::OpenOptions;
use packrat_core::create::Format;
use packrat_core::encoding::NameEncoding;
use packrat_core::extract::{ExtractOptions, Plan, Resolution};
use packrat_core::zip::ZipMethod;
use packrat_core::{codec::stream::Compression, timeutil};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, channel};
use tree::Sort;

/// What the program was asked to do right after it starts (the Explorer menu launches these).
pub enum StartAction {
    None,
    ExtractHere(Vec<PathBuf>),
    ExtractTo(Vec<PathBuf>),
    Test(Vec<PathBuf>),
    Add(Vec<PathBuf>),
    Quick {
        format: String,
        items: Vec<PathBuf>,
    },
    /// A job file written by the unprivileged window (see `admin`).
    Elevated(PathBuf),
}

pub struct StartOptions {
    pub open: Vec<PathBuf>,
    pub demo: bool,
    pub screenshots: Option<PathBuf>,
    pub action: StartAction,
}

pub fn run(opts: StartOptions) -> eframe::Result {
    let icon = egui::IconData {
        rgba: include_bytes!("../../assets/icon64.rgba").to_vec(),
        width: 64,
        height: 64,
    };
    let shots = opts.screenshots.is_some();
    let quiet = is_quiet(&opts);
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Packrat")
        .with_inner_size([1100.0, 700.0])
        .with_min_inner_size([760.0, 480.0])
        .with_icon(Arc::new(icon))
        .with_drag_and_drop(true);
    if shots {
        viewport = viewport.with_resizable(false);
    }
    if quiet {
        // an extraction started from Explorer needs a progress bar, not the whole archive window
        viewport = viewport
            .with_inner_size([600.0, 280.0])
            .with_min_inner_size([520.0, 220.0]);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Packrat",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::install_fonts(&cc.egui_ctx, false);
            Ok(Box::new(App::new(&cc.egui_ctx, opts)))
        }),
    )
}

/// Extractions started from the Explorer menu get a compact window that closes by itself.
fn is_quiet(opts: &StartOptions) -> bool {
    !opts.demo
        && opts.screenshots.is_none()
        && matches!(opts.action, StartAction::ExtractHere(_) | StartAction::ExtractTo(_))
}

pub(crate) struct ExtractDialog {
    pub dest: String,
    pub smart: bool,
    pub open_after: bool,
    pub delete_after: bool,
    pub selected_only: bool,
    pub selected_count: usize,
}

pub(crate) struct ConflictDialog {
    pub plan: Box<Plan>,
    pub opts: Box<ExtractOptions>,
    pub choice: Resolution,
}

pub(crate) struct EncodingDialog {
    pub choice: NameEncoding,
}

/// What to continue with once the password has opened the archive.
pub(crate) enum AfterOpen {
    Nothing,
    /// Show the "extract to…" dialog.
    ExtractDialog,
    /// Check the archive's integrity.
    Verify,
    Extract {
        dest: PathBuf,
        smart: bool,
        selected_only: bool,
    },
}

pub(crate) struct PasswordDialog {
    pub text: String,
    pub show: bool,
    /// A password was tried and did not work.
    pub wrong: bool,
    /// The archive that could not be opened.
    pub path: Option<PathBuf>,
    pub then: AfterOpen,
}

pub(crate) struct RiskDialog {
    pub plan: Box<Plan>,
    pub opts: Box<ExtractOptions>,
}

pub(crate) struct CreateDialog {
    pub password: String,
    pub encrypt_names: bool,
    pub items: Vec<PathBuf>,
    pub format: usize,
    pub level: u32,
    /// Percent of recovery data for ZIP and .prat; 0 = none.
    pub recovery: u32,
    pub output: String,
    pub output_edited: bool,
}

#[derive(Default)]
pub(crate) struct ResultInfo {
    pub ok: bool,
    pub lines: Vec<String>,
    pub details: Vec<String>,
    pub folder: Option<PathBuf>,
    /// Some entries failed because of the password: offer to enter it again.
    pub wrong_password: bool,
    /// The destination refused access: offer to repeat this extraction with administrator rights.
    pub admin: Option<crate::admin::Job>,
    /// The archive could not be opened because its structure is damaged: offer to repair it.
    pub repair: Option<PathBuf>,
}

pub(crate) enum UpdateState {
    Idle,
    Checking,
    Available(update::Release),
    UpToDate,
    Downloading,
    Failed(String),
}

pub(crate) enum UpdateMsg {
    Checked(Result<Option<update::Release>, String>),
    Downloaded(Result<PathBuf, String>),
}

pub(crate) const FORMATS: [(Key, &str); 8] = [
    (Key::FormatZip, "zip"),
    (Key::FormatZipZstd, "zip-zstd"),
    (Key::Format7z, "7z"),
    (Key::FormatPrat, "prat"),
    (Key::FormatTarZst, "tar.zst"),
    (Key::FormatTarLz4, "tar.lz4"),
    (Key::FormatTarGz, "tar.gz"),
    (Key::FormatTarXz, "tar.xz"),
];

pub(crate) struct App {
    pub settings: Settings,
    pub loaded: Option<Loaded>,
    pub job: Option<Job>,
    pub extract: Option<ExtractDialog>,
    pub conflicts: Option<ConflictDialog>,
    pub encoding_dialog: Option<EncodingDialog>,
    pub password_dialog: Option<PasswordDialog>,
    pub risk_dialog: Option<RiskDialog>,
    pub preview: preview::PreviewPane,
    /// Selection and expansion to restore after the archive is reopened (new encoding or password).
    pub carry: Option<(std::collections::HashSet<usize>, std::collections::HashSet<usize>)>,
    pub after_open: AfterOpen,
    /// Entry paths to extract (set by an elevated job).
    pub pending_names: Option<Vec<String>>,
    pub resolution_override: Option<Resolution>,
    /// Repair mode: the archive was opened from its local headers and damaged entries are kept as partial files.
    pub repair_mode: bool,
    pub last_extract: Option<crate::admin::Job>,
    pub create: Option<CreateDialog>,
    pub result: Option<ResultInfo>,
    pub settings_open: bool,
    pub update_open: bool,
    pub update: UpdateState,
    pub update_rx: Option<Receiver<UpdateMsg>>,
    pub download: Arc<(AtomicU64, AtomicU64)>,
    pub sort: Sort,
    pub demo: bool,
    pub cjk_loaded: bool,
    pub toast: Option<(String, std::time::Instant)>,
    pub crash_note: Option<String>,
    pub shots: Option<shots::Runner>,
    pub logo: Option<egui::TextureHandle>,
    /// Archives from one Explorer selection, handled in turn.
    pub queue: Option<queue::Queue>,
    /// The window only exists for the queue: it closes together with the last dialog.
    pub quit_on_close: bool,
    /// Compact window of an Explorer extraction.
    pub quiet: bool,
}

impl App {
    fn new(ctx: &egui::Context, opts: StartOptions) -> Self {
        let settings = Settings::load();
        i18n::set_lang(i18n::Lang::from_code(&settings.language));
        let crash_note = diag::last_crash().and_then(|p| {
            let fresh = std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .map(|t| {
                    timeutil::system_time_to_unix(t)
                        > timeutil::system_time_to_unix(std::time::SystemTime::now()) - 3 * 86_400
                })
                .unwrap_or(false);
            fresh.then(|| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
        });
        let quiet = is_quiet(&opts);
        let mut app = App {
            settings,
            loaded: None,
            job: None,
            extract: None,
            conflicts: None,
            encoding_dialog: None,
            password_dialog: None,
            risk_dialog: None,
            preview: preview::PreviewPane::default(),
            carry: None,
            after_open: AfterOpen::Nothing,
            pending_names: None,
            resolution_override: None,
            repair_mode: false,
            last_extract: None,
            create: None,
            result: None,
            settings_open: false,
            update_open: false,
            update: UpdateState::Idle,
            update_rx: None,
            download: Arc::new((AtomicU64::new(0), AtomicU64::new(0))),
            sort: Sort::default(),
            demo: opts.demo || opts.screenshots.is_some(),
            cjk_loaded: false,
            toast: None,
            crash_note,
            shots: opts.screenshots.map(shots::Runner::new),
            logo: load_logo(ctx),
            queue: None,
            quit_on_close: false,
            quiet,
        };
        if app.demo {
            app.settings.recent = crate::demo::recent_files();
            if app.shots.is_none() {
                app.load_demo(ctx);
            }
        } else if !matches!(opts.action, StartAction::None) {
            app.run_action(ctx, opts.action);
        } else if let Some(p) = opts.open.into_iter().next() {
            app.open_path(ctx, p);
        } else if update::due(&app.settings, now_unix()) {
            app.check_updates(ctx, false);
        }
        app
    }

    /// What the Explorer menu (or an elevated job) asked for.
    fn run_action(&mut self, ctx: &egui::Context, action: StartAction) {
        match action {
            StartAction::None => {}
            StartAction::ExtractHere(items) => self.start_queue(ctx, queue::QueueKind::Here, items, self.quiet),
            StartAction::ExtractTo(items) => self.start_queue(ctx, queue::QueueKind::To, items, self.quiet),
            StartAction::Test(items) => self.start_queue(ctx, queue::QueueKind::Test, items, false),
            StartAction::Add(items) => self.begin_create(items),
            StartAction::Quick { format, items } => self.quick_create(ctx, &format, items),
            StartAction::Elevated(job_file) => self.start_elevated(ctx, &job_file),
        }
    }

    pub fn load_demo(&mut self, ctx: &egui::Context) {
        let (archive, name, len) = crate::demo::archive();
        let loaded = Loaded::new(archive, None, name, len, OpenOptions::default());
        self.adopt(ctx, loaded);
    }

    fn adopt(&mut self, ctx: &egui::Context, loaded: Loaded) {
        let wants_cjk = loaded
            .archive
            .entries()
            .iter()
            .any(|e| e.path.chars().any(|c| (c as u32) >= 0x2E80));
        if wants_cjk && !self.cjk_loaded {
            theme::install_fonts(ctx, true);
            self.cjk_loaded = true;
        }
        if let Some(p) = &loaded.path {
            self.settings.remember(&p.to_string_lossy());
            self.save_settings();
        }
        let mut loaded = loaded;
        if let Some((selected, expanded)) = self.carry.take()
            && let Some(old) = &self.loaded
            && old.archive.entries().len() == loaded.archive.entries().len()
        {
            loaded.selected = selected;
            loaded.expanded = expanded;
        }
        self.preview.clear();
        self.loaded = Some(loaded);
    }

    pub fn open_path(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.open_path_with(ctx, path, OpenOptions::default());
    }

    pub fn open_path_with(&mut self, ctx: &egui::Context, path: PathBuf, opts: OpenOptions) {
        if self.job.is_some() {
            return;
        }
        self.job = Some(Job::spawn(ctx, t(Key::Working).to_owned(), move |_| {
            Outcome::Opened(jobs::open_loaded(path, opts))
        }));
    }

    /// Reopens the archive on screen with different options (a name encoding or a password), keeping the selection.
    pub fn reopen_with(&mut self, ctx: &egui::Context, opts: OpenOptions) {
        let Some(l) = &self.loaded else { return };
        let Some(path) = l.path.clone() else { return };
        self.carry = Some((l.selected.clone(), l.expanded.clone()));
        self.open_path_with(ctx, path, opts);
    }

    pub fn open_or_create(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>) {
        if self.job.is_some() || paths.is_empty() {
            return;
        }
        self.job = Some(Job::spawn(ctx, t(Key::Working).to_owned(), move |_| {
            if paths.len() == 1
                && let Ok(l) = jobs::open_loaded(paths[0].clone(), OpenOptions::default())
            {
                return Outcome::Opened(Ok(l));
            }
            Outcome::NotAnArchive(paths)
        }));
    }

    /// Settings are never written in demo mode (they hold made-up data there).
    pub fn save_settings(&self) {
        if !self.demo {
            self.settings.save();
        }
    }

    pub fn threads(&self) -> usize {
        self.settings.threads
    }

    pub fn check_updates(&mut self, ctx: &egui::Context, user_initiated: bool) {
        if matches!(self.update, UpdateState::Checking | UpdateState::Downloading) {
            return;
        }
        self.update = UpdateState::Checking;
        self.settings.last_update_check = now_unix();
        self.save_settings();
        let (tx, rx) = channel();
        self.update_rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = update::check_latest();
            if let Err(e) = &r {
                diag::warn(&format!("update check failed: {e}"));
            }
            let _ = tx.send(UpdateMsg::Checked(r));
            ctx.request_repaint();
        });
        if user_initiated {
            self.update_open = true;
        }
    }

    pub fn download_update(&mut self, ctx: &egui::Context, rel: update::Release) {
        self.update = UpdateState::Downloading;
        self.download.0.store(0, Ordering::Relaxed);
        self.download.1.store(0, Ordering::Relaxed);
        let (tx, rx) = channel();
        self.update_rx = Some(rx);
        let ctx = ctx.clone();
        let dl = self.download.clone();
        std::thread::spawn(move || {
            let result = std::env::current_exe().map_err(|e| e.to_string()).and_then(|cur| {
                let new = update::download_verified(&rel, &cur, &|done, total| {
                    dl.0.store(done, Ordering::Relaxed);
                    dl.1.store(total, Ordering::Relaxed);
                    ctx.request_repaint();
                })?;
                update::apply(&new, &cur)?;
                Ok(cur)
            });
            match &result {
                Ok(_) => diag::info(&format!("updated to {}", rel.tag)),
                Err(e) => diag::error(&format!("update failed: {e}")),
            }
            let _ = tx.send(UpdateMsg::Downloaded(result));
            ctx.request_repaint();
        });
    }

    fn poll_update(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.update_rx else { return };
        let Ok(msg) = rx.try_recv() else { return };
        self.update_rx = None;
        match msg {
            UpdateMsg::Checked(Ok(Some(rel))) => self.update = UpdateState::Available(rel),
            UpdateMsg::Checked(Ok(None)) => self.update = UpdateState::UpToDate,
            UpdateMsg::Checked(Err(e)) => self.update = UpdateState::Failed(e),
            UpdateMsg::Downloaded(Ok(exe)) => {
                let _ = std::process::Command::new(exe).spawn();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            UpdateMsg::Downloaded(Err(e)) => self.update = UpdateState::Failed(e),
        }
    }

    pub(crate) fn poll_job(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.job else { return };
        let Ok(outcome) = job.rx.try_recv() else { return };
        self.job = None;
        match outcome {
            Outcome::Opened(Ok(l)) => {
                self.adopt(ctx, *l);
                let then = std::mem::replace(&mut self.after_open, AfterOpen::Nothing);
                match then {
                    AfterOpen::Extract {
                        dest,
                        smart,
                        selected_only,
                    } => self.start_extract(ctx, dest, smart, selected_only),
                    AfterOpen::ExtractDialog => self.begin_extract(false),
                    AfterOpen::Verify => self.start_verify(ctx),
                    AfterOpen::Nothing => {}
                }
            }
            Outcome::Opened(Err(fail)) => {
                diag::warn(&format!("open failed: {}", fail.message));
                self.carry = None;
                if fail.needs_password {
                    let was_wrong = fail.message.contains("wrong password");
                    let then = std::mem::replace(&mut self.after_open, AfterOpen::Nothing);
                    self.password_dialog = Some(PasswordDialog {
                        text: String::new(),
                        show: false,
                        wrong: was_wrong,
                        path: Some(fail.path),
                        then,
                    });
                } else {
                    self.after_open = AfterOpen::Nothing;
                    let repair = fail.can_repair.then(|| fail.path.clone());
                    self.result = Some(ResultInfo {
                        ok: false,
                        lines: vec![tf(Key::ErrorGeneric, &[&fail.message])]
                            .into_iter()
                            .chain(repair.iter().map(|_| t(Key::RepairText).to_owned()))
                            .collect(),
                        repair,
                        ..Default::default()
                    });
                }
            }
            Outcome::NotAnArchive(paths) => self.begin_create(paths),
            Outcome::Planned { plan, opts } => {
                if !plan.risks.is_empty() && !opts.accept_risks {
                    self.risk_dialog = Some(RiskDialog { plan, opts });
                } else {
                    self.after_risks(ctx, plan, opts);
                }
            }
            Outcome::Extracted { report, secs, dest } => self.finish_extract(report, secs, dest),
            Outcome::Created { result, output, secs } => self.finish_create(result, output, secs),
            Outcome::Verified {
                report,
                sha256,
                secs,
                files,
            } => self.finish_verify(*report, sha256, secs, files),
        }
    }

    /// The plan has no risks (or they were accepted): ask about conflicts, then extract.
    pub fn after_risks(&mut self, ctx: &egui::Context, plan: Box<Plan>, opts: Box<ExtractOptions>) {
        if plan.conflicts.is_empty() {
            self.run_execute(ctx, *plan, *opts);
        } else {
            self.conflicts = Some(ConflictDialog {
                plan,
                opts,
                choice: Resolution::Skip,
            });
        }
    }

    pub fn format_from_index(i: usize) -> Format {
        match FORMATS[i].1 {
            "zip" => Format::Zip(ZipMethod::Deflate),
            "zip-zstd" => Format::Zip(ZipMethod::Zstd),
            "7z" => Format::SevenZ,
            "prat" => Format::Prat,
            "tar.zst" => Format::Tar(Compression::Zst),
            "tar.lz4" => Format::Tar(Compression::Lz4),
            "tar.gz" => Format::Tar(Compression::Gz),
            _ => Format::Tar(Compression::Xz),
        }
    }

    /// What the compact window of an Explorer extraction shows behind its dialogs.
    fn compact_view(&mut self, ui: &mut Ui) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::PALETTE.bg).inner_margin(16.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.logo {
                        ui.image((logo.id(), egui::vec2(28.0, 28.0)));
                    }
                    ui.label(egui::RichText::new("Packrat").strong().size(18.0));
                });
                if let Some(q) = &self.queue {
                    ui.add_space(8.0);
                    if q.total() > 1 {
                        ui.label(tf(
                            Key::BatchTitle,
                            &[&q.position().to_string(), &q.total().to_string()],
                        ));
                    }
                    ui.add(egui::Label::new(theme::dim(q.current_name())).truncate());
                }
            });
    }

    pub fn show_toast(&mut self, text: String) {
        self.toast = Some((text, std::time::Instant::now()));
    }
}

fn load_logo(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let img = image::load_from_memory(include_bytes!("../../assets/icon.png"))
        .ok()?
        .to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    Some(ctx.load_texture(
        "logo",
        egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw()),
        egui::TextureOptions::LINEAR,
    ))
}

pub(crate) fn now_unix() -> i64 {
    timeutil::system_time_to_unix(std::time::SystemTime::now())
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_job(&ctx);
        self.advance_queue(&ctx);
        self.poll_update(&ctx);
        self.handle_drops(&ctx);
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::O)) && self.job.is_none() {
            self.pick_archive(&ctx);
        }
        if self.job.is_some() || matches!(self.update, UpdateState::Downloading | UpdateState::Checking) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        if self.quiet {
            self.compact_view(ui);
        } else {
            self.top_bar(ui);
            self.status_bar(ui);
            egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(theme::PALETTE.bg))
                .show(ui, |ui| {
                    ui.add_enabled_ui(self.job.is_none(), |ui| {
                        if self.loaded.is_some() {
                            self.archive_view(ui);
                        } else {
                            self.welcome_view(ui);
                        }
                    });
                });
        }

        self.pump_preview(&ctx);
        self.dialogs(&ctx);
        self.drop_overlay(&ctx);
        shots::tick(self, &ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packrat_core::Password;
    use packrat_core::create::{CreateOptions, create_archive};

    fn wait_for_job(app: &mut App, ctx: &egui::Context) {
        for _ in 0..4000 {
            app.poll_job(ctx);
            if app.job.is_none() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("the job did not finish");
    }

    fn make_archive(dir: &std::path::Path, format: Format) -> PathBuf {
        let src = dir.join("proj");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "alpha").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), "beta").unwrap();
        let archive = dir.join(format!("proj.{}", format.extension()));
        create_archive(
            &archive,
            &[src],
            &CreateOptions::new(format),
            &packrat_core::Progress::new(),
        )
        .unwrap();
        archive
    }

    #[test]
    fn open_extract_and_conflicts_through_the_app_logic() {
        crate::settings::use_test_data_dir();
        let dir = tempfile::tempdir().unwrap();
        let archive = make_archive(dir.path(), Format::Zip(ZipMethod::Deflate));
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![archive],
                demo: false,
                screenshots: None,
                action: StartAction::None,
            },
        );
        wait_for_job(&mut app, &ctx);
        assert!(app.loaded.is_some(), "archive opened");

        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        app.start_extract(&ctx, dest.clone(), true, false);
        wait_for_job(&mut app, &ctx); // plan
        assert!(app.conflicts.is_none());
        wait_for_job(&mut app, &ctx); // execute
        let r = app.result.take().expect("result is shown");
        assert!(r.ok, "{:?}", r.lines);
        assert_eq!(std::fs::read_to_string(dest.join("proj/sub/b.txt")).unwrap(), "beta");
        assert!(!dest.join("proj/proj").exists());

        // second run: files exist, so the user is asked
        std::fs::write(dest.join("proj/a.txt"), "edited").unwrap();
        app.start_extract(&ctx, dest.clone(), true, false);
        wait_for_job(&mut app, &ctx);
        let c = app.conflicts.as_ref().expect("conflict dialog");
        assert_eq!(c.plan.conflicts.len(), 2);
        assert_eq!(
            std::fs::read_to_string(dest.join("proj/a.txt")).unwrap(),
            "edited",
            "nothing written before the decision"
        );
        let c = app.conflicts.take().unwrap();
        let mut opts = c.opts;
        opts.default_resolution = Resolution::KeepBoth;
        app.run_execute(&ctx, *c.plan, *opts);
        wait_for_job(&mut app, &ctx);
        assert_eq!(std::fs::read_to_string(dest.join("proj/a.txt")).unwrap(), "edited");
        assert_eq!(std::fs::read_to_string(dest.join("proj/a (2).txt")).unwrap(), "alpha");
    }

    #[test]
    fn dropped_non_archive_opens_the_create_dialog() {
        crate::settings::use_test_data_dir();
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("notes.txt");
        std::fs::write(&plain, "just text").unwrap();
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.loaded = None;
        app.open_or_create(&ctx, vec![plain.clone()]);
        wait_for_job(&mut app, &ctx);
        let c = app.create.as_ref().expect("create dialog");
        assert_eq!(c.items, vec![plain]);
    }

    #[test]
    fn create_through_the_app_logic_produces_a_readable_archive() {
        crate::settings::use_test_data_dir();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.txt");
        std::fs::write(&file, "x".repeat(10_000)).unwrap();
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.begin_create(vec![file]);
        let out = dir.path().join("data.tar.zst");
        {
            let c = app.create.as_mut().unwrap();
            c.format = FORMATS.iter().position(|(_, n)| *n == "tar.zst").unwrap();
            c.output = out.to_string_lossy().into_owned();
            c.output_edited = true;
        }
        app.start_create_for_test(&ctx);
        wait_for_job(&mut app, &ctx);
        assert!(app.result.as_ref().is_some_and(|r| r.ok));
        assert!(
            packrat_core::open::open(&out)
                .unwrap()
                .entries()
                .iter()
                .any(|e| e.path == "data.txt")
        );
    }

    #[test]
    fn a_prat_archive_with_a_password_and_recovery_data_is_made_and_remembered() {
        crate::settings::use_test_data_dir();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.txt");
        std::fs::write(&file, "classified ".repeat(5_000)).unwrap();
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.begin_create(vec![file]);
        let out = dir.path().join("secret.prat");
        {
            let c = app.create.as_mut().unwrap();
            c.format = FORMATS.iter().position(|(_, n)| *n == "prat").unwrap();
            c.password = "pw-123".into();
            c.recovery = 8;
            c.output = out.to_string_lossy().into_owned();
            c.output_edited = true;
        }
        app.start_create_for_test(&ctx);
        wait_for_job(&mut app, &ctx);
        assert!(
            app.result.as_ref().is_some_and(|r| r.ok),
            "{:?}",
            app.result.as_ref().map(|r| &r.lines)
        );
        // encrypted: nothing opens without the password, and it opens with it
        assert!(matches!(
            packrat_core::open::open(&out).err(),
            Some(packrat_core::Error::PasswordRequired)
        ));
        let opened = packrat_core::open::open_with(&out, &OpenOptions::default().with_password("pw-123")).unwrap();
        assert!(opened.entries().iter().any(|e| e.path == "secret.txt"));
        // the recovery data is there, and the choice is remembered for the next time
        assert!(packrat_core::prat::recover::recovery_info(&out).is_some());
        assert_eq!(app.settings.recovery, 8);
        assert_eq!(app.settings.default_format, "prat");
    }

    #[test]
    fn recovery_is_not_added_to_formats_that_cannot_hold_it() {
        crate::settings::use_test_data_dir();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.txt");
        std::fs::write(&file, "x".repeat(10_000)).unwrap();
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.begin_create(vec![file]);
        let out = dir.path().join("data.7z");
        {
            let c = app.create.as_mut().unwrap();
            c.format = FORMATS.iter().position(|(_, n)| *n == "7z").unwrap();
            c.recovery = 10; // left over from a previous choice: must be ignored for 7z, not make the job fail
            c.output = out.to_string_lossy().into_owned();
            c.output_edited = true;
        }
        app.start_create_for_test(&ctx);
        wait_for_job(&mut app, &ctx);
        assert!(app.result.as_ref().is_some_and(|r| r.ok));
        assert!(out.exists());
    }

    fn app_with(ctx: &egui::Context, path: PathBuf) -> App {
        crate::settings::use_test_data_dir();
        let mut app = App::new(
            ctx,
            StartOptions {
                open: vec![path],
                demo: false,
                screenshots: None,
                action: StartAction::None,
            },
        );
        wait_for_job(&mut app, ctx);
        app
    }

    #[test]
    fn a_bomb_is_not_extracted_until_the_user_accepts_the_risk() {
        use packrat_core::testkit::{RawEntry, raw_zip};
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("bomb.zip");
        std::fs::write(
            &zip,
            raw_zip(&[RawEntry::file("zeros.bin", vec![0u8; 80 << 20]).deflated()]),
        )
        .unwrap();
        let ctx = egui::Context::default();
        let mut app = app_with(&ctx, zip);
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        app.start_extract(&ctx, dest.clone(), false, false);
        wait_for_job(&mut app, &ctx);
        let risk = app.risk_dialog.take().expect("the warning dialog is shown");
        assert!(!risk.plan.risks.is_empty());
        assert!(
            std::fs::read_dir(&dest).unwrap().next().is_none(),
            "nothing is written while the dialog is open"
        );

        // "continue at my own risk"
        let mut opts = risk.opts;
        opts.accept_risks = true;
        app.after_risks(&ctx, risk.plan, opts);
        wait_for_job(&mut app, &ctx);
        assert!(app.result.as_ref().is_some_and(|r| r.ok));
        assert_eq!(std::fs::metadata(dest.join("zeros.bin")).unwrap().len(), 80 << 20);
    }

    #[test]
    fn an_encrypted_archive_asks_for_the_password_and_then_extracts() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("vault");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("note.txt"), "top secret").unwrap();
        let archive = dir.path().join("vault.zip");
        let mut copts = CreateOptions::new(Format::Zip(ZipMethod::Deflate));
        copts.password = Some(Password::new("open sesame"));
        create_archive(&archive, &[src], &copts, &packrat_core::Progress::new()).unwrap();

        let ctx = egui::Context::default();
        let mut app = app_with(&ctx, archive);
        assert!(app.loaded.as_ref().unwrap().has_encrypted());
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        app.start_extract(&ctx, dest.clone(), true, false);
        assert!(app.job.is_none(), "no work starts before the password is known");
        let d = app.password_dialog.take().expect("password dialog");

        // the user types the password (what the dialog does on OK)
        app.after_open = d.then;
        app.reopen_with(&ctx, OpenOptions::default().with_password("open sesame"));
        wait_for_job(&mut app, &ctx); // reopen, then the extraction plan starts
        wait_for_job(&mut app, &ctx); // plan
        wait_for_job(&mut app, &ctx); // extract
        assert!(
            app.result.as_ref().is_some_and(|r| r.ok),
            "{:?}",
            app.result.as_ref().map(|r| &r.lines)
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("vault/note.txt")).unwrap(),
            "top secret"
        );
        assert!(app.loaded.as_ref().unwrap().opts.password.is_some());
    }

    #[test]
    fn a_wrong_password_is_reported_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("v");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), "x").unwrap();
        let archive = dir.path().join("v.7z");
        let mut copts = CreateOptions::new(Format::SevenZ);
        copts.password = Some(Password::new("right"));
        create_archive(&archive, &[src], &copts, &packrat_core::Progress::new()).unwrap();

        let ctx = egui::Context::default();
        crate::settings::use_test_data_dir();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.loaded = None;
        app.open_path(&ctx, archive.clone());
        wait_for_job(&mut app, &ctx);
        assert!(app.loaded.is_none());
        let d = app
            .password_dialog
            .take()
            .expect("the encrypted header asks for a password");
        assert!(!d.wrong);

        app.open_path_with(&ctx, archive.clone(), OpenOptions::default().with_password("nope"));
        wait_for_job(&mut app, &ctx);
        assert!(
            app.password_dialog.as_ref().is_some_and(|d| d.wrong),
            "the dialog says the password did not work"
        );

        app.open_path_with(&ctx, archive, OpenOptions::default().with_password("right"));
        wait_for_job(&mut app, &ctx);
        assert!(app.loaded.is_some());
    }

    #[test]
    fn choosing_another_name_encoding_reopens_the_archive_and_keeps_the_selection() {
        use packrat_core::encoding::NameEncoding;
        use packrat_core::testkit::{RawEntry, raw_zip};
        let dir = tempfile::tempdir().unwrap();
        let name = encoding_rs::IBM866.encode("Документы/Отчёт.txt").0.into_owned();
        let zip = dir.path().join("old.zip");
        std::fs::write(&zip, raw_zip(&[RawEntry::file(name, "x")])).unwrap();
        let ctx = egui::Context::default();
        let mut app = app_with(&ctx, zip);
        let l = app.loaded.as_mut().unwrap();
        assert_eq!(l.archive.legacy_names().unwrap().current, NameEncoding::Cp866);
        assert_eq!(l.archive.entries()[0].path, "Документы/Отчёт.txt");
        l.selected.insert(1);

        app.reopen_with(&ctx, OpenOptions::default().with_encoding(NameEncoding::Win1251));
        wait_for_job(&mut app, &ctx);
        let l = app.loaded.as_ref().unwrap();
        assert_eq!(l.archive.legacy_names().unwrap().current, NameEncoding::Win1251);
        assert_ne!(l.archive.entries()[0].path, "Документы/Отчёт.txt");
        assert!(l.selected.contains(&1), "the selection survives the reopen");
    }

    #[test]
    fn selecting_one_file_prepares_its_preview_without_extracting() {
        use packrat_core::testkit::{RawEntry, raw_zip};
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("p.zip");
        std::fs::write(
            &zip,
            raw_zip(&[
                RawEntry::dir("src/"),
                RawEntry::file("src/main.rs", "fn main() { let x = 1; }\n").deflated(),
            ]),
        )
        .unwrap();
        let ctx = egui::Context::default();
        let mut app = app_with(&ctx, zip);
        let node = app
            .loaded
            .as_ref()
            .unwrap()
            .tree
            .nodes
            .iter()
            .position(|n| n.name == "main.rs")
            .unwrap();
        app.loaded.as_mut().unwrap().selected.insert(node);
        for _ in 0..400 {
            app.pump_preview(&ctx);
            if app.preview.shown.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let shown = app.preview.shown.as_ref().expect("preview is ready");
        assert!(matches!(shown.body, preview::Body::Text(_)));

        // two selected files: no preview target
        let other = app
            .loaded
            .as_ref()
            .unwrap()
            .tree
            .nodes
            .iter()
            .position(|n| n.name == "src")
            .unwrap();
        app.loaded.as_mut().unwrap().selected.insert(other);
        app.pump_preview(&ctx);
        assert_eq!(app.preview.want, None);
    }

    #[test]
    fn explorer_actions_extract_check_and_compress() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("pack");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "alpha").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), "beta").unwrap();
        let ctx = egui::Context::default();
        crate::settings::use_test_data_dir();

        // "Compress to .tar.zst": no dialog, the archive appears next to the folder
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::Quick {
                    format: "tar.zst".into(),
                    items: vec![src.clone()],
                },
            },
        );
        wait_for_job(&mut app, &ctx);
        let archive = dir.path().join("pack.tar.zst");
        assert!(archive.exists(), "the quick archive is created");
        assert!(app.result.as_ref().is_some_and(|r| r.ok));

        // "Extract here (smart)": into the archive's own folder, without Folder\Folder
        std::fs::remove_dir_all(&src).unwrap();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::ExtractHere(vec![archive.clone()]),
            },
        );
        for _ in 0..3 {
            wait_for_job(&mut app, &ctx);
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("pack/sub/b.txt")).unwrap(),
            "beta"
        );
        assert!(!dir.path().join("pack/pack").exists());

        // "Test archive"
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::Test(vec![archive.clone()]),
            },
        );
        for _ in 0..2 {
            wait_for_job(&mut app, &ctx);
        }
        let r = app.result.take().expect("the check reports");
        assert!(
            r.ok && r.lines.iter().any(|l| l.contains("SHA-256") || l.contains("SHA")),
            "{:?}",
            r.lines
        );

        // "Add to archive…" opens the create dialog with the files
        let app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::Add(vec![archive]),
            },
        );
        assert_eq!(app.create.as_ref().unwrap().items.len(), 1);
    }

    /// Several archives from one Explorer selection; `set` tunes the settings before anything starts.
    fn run_queue(
        action: StartAction,
        set: impl FnOnce(&mut Settings),
        on_problem: &mut dyn FnMut(&mut App),
    ) -> (App, egui::Context, tempfile::TempDir) {
        let data = crate::settings::use_private_test_data_dir();
        let ctx = egui::Context::default();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action,
            },
        );
        set(&mut app.settings);
        for _ in 0..4000 {
            app.poll_job(&ctx);
            if let Some(c) = app.conflicts.take() {
                // a file is in the way: keep the existing one
                let mut opts = c.opts;
                opts.default_resolution = Resolution::Skip;
                app.run_execute(&ctx, *c.plan, *opts);
            }
            if app.job.is_none() && app.result.is_some() && app.queue.is_some() {
                on_problem(&mut app);
            }
            app.advance_queue(&ctx);
            if app.queue.is_none() {
                return (app, ctx, data);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("the queue did not finish");
    }

    fn zip_with(dir: &std::path::Path, name: &str, file: &str, text: &str) -> PathBuf {
        let src = dir.join(format!("{name}-src"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join(file), text).unwrap();
        let archive = dir.join(format!("{name}.zip"));
        create_archive(
            &archive,
            &[src.join(file)],
            &CreateOptions::new(Format::Zip(ZipMethod::Deflate)),
            &packrat_core::Progress::new(),
        )
        .unwrap();
        archive
    }

    #[test]
    fn a_selection_of_archives_is_extracted_in_one_run() {
        let dir = tempfile::tempdir().unwrap();
        let archives: Vec<PathBuf> = (0..3)
            .map(|i| zip_with(dir.path(), &format!("a{i}"), &format!("f{i}.txt"), &format!("body {i}")))
            .collect();
        let (app, ..) = run_queue(
            StartAction::ExtractHere(archives),
            |s| s.open_after_extract = false,
            &mut |_| panic!("no problems expected"),
        );
        for i in 0..3 {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(format!("f{i}.txt"))).unwrap(),
                format!("body {i}")
            );
        }
        let r = app.result.as_ref().expect("one summary at the end");
        assert!(r.ok && r.lines[0].contains('3'), "{:?}", r.lines);
        assert!(app.quit_on_close, "an Explorer run closes the window after the summary");
    }

    #[test]
    fn a_bad_archive_does_not_stop_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let good = zip_with(dir.path(), "good", "g.txt", "fine");
        let bad = dir.path().join("bad.zip");
        std::fs::write(&bad, b"this is not an archive").unwrap();
        let mut seen = 0;
        let (app, ..) = run_queue(
            StartAction::ExtractHere(vec![bad, good]),
            |s| s.open_after_extract = false,
            &mut |app| {
                seen += 1;
                app.result = None;
            },
        );
        assert_eq!(seen, 1, "the unreadable archive is reported once");
        assert_eq!(std::fs::read_to_string(dir.path().join("g.txt")).unwrap(), "fine");
        let r = app.result.as_ref().expect("summary");
        assert!(
            !r.ok && r.details.iter().any(|d| d.contains("bad.zip")),
            "{:?}",
            r.details
        );
    }

    #[test]
    fn archives_go_to_the_folder_chosen_once() {
        let dir = tempfile::tempdir().unwrap();
        let archives = vec![
            zip_with(dir.path(), "one", "1.txt", "1"),
            zip_with(dir.path(), "two", "2.txt", "2"),
        ];
        let out = dir.path().join("out");
        let ctx = egui::Context::default();
        let _data = crate::settings::use_private_test_data_dir();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::ExtractTo(archives),
            },
        );
        app.settings.open_after_extract = false;
        for _ in 0..4000 {
            app.poll_job(&ctx);
            if let Some(d) = app.extract.as_mut() {
                // the dialog appears for the first archive only
                d.dest = out.to_string_lossy().into_owned();
                let (dest, smart) = (PathBuf::from(&d.dest), d.smart);
                app.extract = None;
                app.queue.as_mut().unwrap().remember_dest(dest.clone(), smart);
                app.start_extract(&ctx, dest, smart, false);
            }
            app.advance_queue(&ctx);
            if app.queue.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(app.queue.is_none(), "the queue finished");
        assert_eq!(std::fs::read_to_string(out.join("1.txt")).unwrap(), "1");
        assert_eq!(std::fs::read_to_string(out.join("2.txt")).unwrap(), "2");
    }

    #[test]
    fn a_clean_extraction_can_move_the_archive_to_the_recycle_bin() {
        let dir = tempfile::tempdir().unwrap();
        let keep = zip_with(dir.path(), "keep", "k.txt", "stay");
        let gone = zip_with(dir.path(), "gone", "g.txt", "go");
        let (..) = run_queue(
            StartAction::ExtractHere(vec![gone.clone()]),
            |s| {
                s.open_after_extract = false;
                s.delete_after_extract = true;
            },
            &mut |_| {},
        );
        assert_eq!(std::fs::read_to_string(dir.path().join("g.txt")).unwrap(), "go");
        assert!(!gone.exists(), "the extracted archive is gone");
        assert!(keep.exists());

        // a partial result must keep the archive: the existing file is skipped
        std::fs::write(dir.path().join("k.txt"), "stay").unwrap();
        let again = zip_with(dir.path(), "again", "k.txt", "other");
        let (..) = run_queue(
            StartAction::ExtractHere(vec![again.clone()]),
            |s| {
                s.open_after_extract = false;
                s.delete_after_extract = true;
            },
            &mut |app| app.result = None,
        );
        assert!(again.exists(), "nothing is deleted when files were skipped");
        assert_eq!(std::fs::read_to_string(dir.path().join("k.txt")).unwrap(), "stay");
    }

    #[test]
    fn an_elevated_job_extracts_what_it_describes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("keep.txt"), "wanted").unwrap();
        std::fs::write(src.join("skip.txt"), "unwanted").unwrap();
        let archive = dir.path().join("docs.zip");
        create_archive(
            &archive,
            &[src],
            &CreateOptions::new(Format::Zip(ZipMethod::Deflate)),
            &packrat_core::Progress::new(),
        )
        .unwrap();

        let dest = dir.path().join("protected-place");
        std::fs::create_dir(&dest).unwrap();
        let job = crate::admin::Job {
            archive,
            dest: dest.clone(),
            smart: false,
            entries: Some(vec!["docs/keep.txt".into()]),
            resolution: "skip".into(),
        };
        let file = crate::admin::write(&job).unwrap();
        let ctx = egui::Context::default();
        crate::settings::use_test_data_dir();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: false,
                screenshots: None,
                action: StartAction::Elevated(file.clone()),
            },
        );
        for _ in 0..3 {
            wait_for_job(&mut app, &ctx);
        }
        assert!(!file.exists(), "the job file is consumed");
        assert_eq!(std::fs::read_to_string(dest.join("docs/keep.txt")).unwrap(), "wanted");
        assert!(
            !dest.join("docs/skip.txt").exists(),
            "only the described entries are extracted"
        );
    }

    #[test]
    fn a_damaged_zip_offers_repair_and_the_repair_extracts_what_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("d");
        std::fs::create_dir_all(&src).unwrap();
        for i in 0..6 {
            std::fs::write(src.join(format!("f{i}.txt")), format!("file {i} ").repeat(5000)).unwrap();
        }
        let whole = dir.path().join("whole.zip");
        create_archive(
            &whole,
            &[src],
            &CreateOptions::new(Format::Zip(ZipMethod::Deflate)),
            &packrat_core::Progress::new(),
        )
        .unwrap();
        let bytes = std::fs::read(&whole).unwrap();
        let cut = dir.path().join("cut.zip");
        std::fs::write(&cut, &bytes[..bytes.len() * 3 / 4]).unwrap();

        let ctx = egui::Context::default();
        crate::settings::use_test_data_dir();
        let mut app = App::new(
            &ctx,
            StartOptions {
                open: vec![],
                demo: true,
                screenshots: None,
                action: StartAction::None,
            },
        );
        app.demo = false;
        app.loaded = None;
        app.open_path(&ctx, cut.clone());
        wait_for_job(&mut app, &ctx);
        let r = app.result.take().expect("open failed");
        assert_eq!(r.repair.as_ref(), Some(&cut), "repair is offered");

        app.repair_open(&ctx, cut);
        wait_for_job(&mut app, &ctx);
        assert!(app.loaded.as_ref().unwrap().archive.is_recovered());
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        app.start_extract(&ctx, dest.clone(), false, false);
        wait_for_job(&mut app, &ctx);
        wait_for_job(&mut app, &ctx);
        let intact = (0..6).filter(|i| dest.join(format!("d/f{i}.txt")).exists()).count();
        assert!(intact >= 3, "{intact} files recovered");
    }
}
