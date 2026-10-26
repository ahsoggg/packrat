//! `Packrat.exe --screenshots <dir>`: walks through a fixed set of scenes with made-up data and saves each one as
//! a PNG. Used to regenerate `docs/screenshots`.

use super::jobs::Loaded;
use super::{App, ResultInfo, RiskDialog};
use eframe::egui;
use packrat_core::OpenOptions;
use packrat_core::extract::{ExtractOptions, Plan};
use packrat_core::safety::Risk;
use std::path::PathBuf;

const SCENES: [&str; 9] = [
    "01-welcome",
    "02-archive-code",
    "03-preview-image",
    "04-encoding",
    "05-bomb-warning",
    "06-extract",
    "07-create",
    "08-settings",
    "09-result",
];
const SETTLE_FRAMES: u32 = 10;

pub struct Runner {
    dir: PathBuf,
    step: usize,
    frames: u32,
    requested: bool,
}

impl Runner {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self {
            dir,
            step: 0,
            frames: 0,
            requested: false,
        }
    }
}

fn select_by_name(app: &mut App, names: &[&str]) {
    if let Some(l) = app.loaded.as_mut() {
        l.expanded = l.tree.dir_ids().collect();
        l.selected = l
            .tree
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| names.contains(&n.name.as_str()))
            .map(|(i, _)| i)
            .collect();
    }
}

fn fake_risks() -> Vec<Risk> {
    vec![
        Risk::HighRatio {
            path: "Заря/assets/video/intro.bin".into(),
            ratio: 1031.0,
            size: 4_800_000_000,
        },
        Risk::NotEnoughSpace {
            need: 4_800_000_000,
            free: 2_100_000_000,
        },
        Risk::OverlappingEntries { count: 38 },
    ]
}

fn setup(app: &mut App, ctx: &egui::Context, step: usize) {
    app.extract = None;
    app.create = None;
    app.result = None;
    app.risk_dialog = None;
    app.encoding_dialog = None;
    app.settings_open = false;
    app.preview.clear();
    if step == 0 {
        app.loaded = None;
        return;
    }
    if step != 3 && app.loaded.as_ref().is_none_or(|l| l.name != "Проект-Заря.zip") {
        app.load_demo(ctx);
    }
    match step {
        1 => select_by_name(app, &["main.rs"]),
        2 => select_by_name(app, &["sky.png"]),
        3 => {
            let (archive, name, len) = crate::demo::legacy_archive();
            app.loaded = Some(Loaded::new(archive, None, name, len, OpenOptions::default()));
            select_by_name(app, &[]);
            app.open_encoding_dialog();
        }
        4 => {
            select_by_name(app, &["README.md"]);
            let opts = ExtractOptions::new(r"D:\Распаковано", "Проект-Заря.zip");
            let plan = Plan {
                base: PathBuf::from(r"D:\Распаковано"),
                layout: None,
                items: vec![],
                blocked: vec![],
                conflicts: vec![],
                total_bytes: 4_800_000_000,
                risks: fake_risks(),
            };
            app.risk_dialog = Some(RiskDialog {
                plan: Box::new(plan),
                opts: Box::new(opts),
            });
        }
        5 => {
            select_by_name(app, &["changelog.md", "guide.md"]);
            app.begin_extract(true);
        }
        6 => {
            select_by_name(app, &["main.rs"]);
            app.begin_create(vec![
                PathBuf::from(r"D:\Фото\Отпуск-2024"),
                PathBuf::from(r"D:\Фото\паспорт-скан.jpg"),
                PathBuf::from(r"D:\Документы\договор.pdf"),
            ]);
            if let Some(c) = app.create.as_mut() {
                c.level = 6;
                c.format = super::FORMATS.iter().position(|(_, n)| *n == "prat").unwrap_or(2);
                c.recovery = 5;
                c.password = "пароль-на-архив".into();
            }
        }
        7 => {
            select_by_name(app, &["main.rs"]);
            app.settings_open = true;
        }
        8 => {
            select_by_name(app, &["main.rs"]);
            app.result = Some(ResultInfo {
                ok: false,
                lines: vec![
                    crate::i18n::tf(crate::i18n::Key::DoneExtract, &["31", "1,1 МБ", "0.4"]),
                    crate::i18n::tf(crate::i18n::Key::BlockedEntries, &["3"]),
                ],
                details: vec![
                    "⛔ ../../Windows/System32/evil.dll — '..' component (path traversal)".into(),
                    "⛔ C:\\autoexec.bat — drive letter in the path".into(),
                    "⛔ CON — reserved Windows device name 'CON'".into(),
                ],
                folder: None,
                ..Default::default()
            });
        }
        _ => {}
    }
}

pub(super) fn tick(app: &mut App, ctx: &egui::Context) {
    let Some(mut r) = app.shots.take() else { return };
    ctx.request_repaint();
    ctx.global_style_mut(|s| s.animation_time = 0.0);
    if r.step >= SCENES.len() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        app.shots = Some(r);
        return;
    }
    if r.frames == 0 {
        setup(app, ctx, r.step);
    }
    r.frames += 1;
    // wait until the preview (a worker thread) is ready and its texture has been uploaded
    if r.frames >= SETTLE_FRAMES && !r.requested && !app.preview.is_loading() && app.job.is_none() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        r.requested = true;
    }
    let image = ctx.input(|i| {
        i.events.iter().find_map(|e| match e {
            egui::Event::Screenshot { image, .. } => Some(image.clone()),
            _ => None,
        })
    });
    if let Some(img) = image {
        let [w, h] = img.size;
        let rgba: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
        let path = r.dir.join(format!("{}.png", SCENES[r.step]));
        match image::save_buffer(&path, &rgba, w as u32, h as u32, image::ColorType::Rgba8) {
            Ok(()) => crate::winint::console_print(&format!("saved {}\n", path.display())),
            Err(e) => crate::winint::console_print(&format!("cannot save {}: {e}\n", path.display())),
        }
        r.step += 1;
        r.frames = 0;
        r.requested = false;
    }
    app.shots = Some(r);
}
