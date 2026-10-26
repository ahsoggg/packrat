//! Localization table: every string the UI shows lives here, in Russian and English.
//! `{0}`, `{1}` are positional arguments filled by `tf`.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub fn from_code(code: &str) -> Lang {
        if code.eq_ignore_ascii_case("en") {
            Lang::En
        } else {
            Lang::Ru
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(lang: Lang) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    if CURRENT.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Ru
    }
}

macro_rules! strings {
    ($($key:ident => ($ru:expr, $en:expr),)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Key { $($key),* }

        impl Key {
            #[cfg(test)]
            pub const ALL: &'static [Key] = &[$(Key::$key),*];

            pub fn text(self, lang: Lang) -> &'static str {
                match (self, lang) {
                    $((Key::$key, Lang::Ru) => $ru, (Key::$key, Lang::En) => $en,)*
                }
            }
        }
    };
}

strings! {
    AppTitle => ("Packrat", "Packrat"),
    Open => ("Открыть…", "Open…"),
    Extract => ("Распаковать", "Extract"),
    ExtractSmartHere => ("Умно рядом с архивом", "Smart extract here"),
    ExtractTo => ("Распаковать в папку…", "Extract to folder…"),
    CreateArchive => ("Создать архив…", "Create archive…"),
    CloseArchive => ("Закрыть", "Close"),
    Settings => ("Настройки", "Settings"),
    Update => ("Обновление", "Update"),
    Cancel => ("Отмена", "Cancel"),
    Close => ("Закрыть", "Close"),
    Ok => ("ОК", "OK"),
    Browse => ("Обзор…", "Browse…"),
    WelcomeTitle => ("Перетащите архив в окно", "Drop an archive onto the window"),
    WelcomeHint => (
        "Поддерживаются ZIP, 7z, TAR, TAR.GZ/ZST/XZ/LZ4, а также одиночные GZ, BZ2, XZ, ZST, LZ4",
        "ZIP, 7z, TAR, TAR.GZ/ZST/XZ/LZ4 and single GZ, BZ2, XZ, ZST, LZ4 files are supported"
    ),
    Recent => ("Недавние", "Recent"),
    ColName => ("Имя", "Name"),
    ColSize => ("Размер", "Size"),
    ColPacked => ("Сжато", "Packed"),
    ColRatio => ("Степень", "Ratio"),
    ColModified => ("Изменён", "Modified"),
    ColMethod => ("Метод", "Method"),
    StatusArchive => ("{0} · {1} файлов, {2} папок · {3} → {4}", "{0} · {1} files, {2} folders · {3} → {4}"),
    StatusSelected => ("выбрано: {0}", "selected: {0}"),
    ExtractTitle => ("Распаковка", "Extract"),
    ExtractDestination => ("Куда распаковать", "Destination"),
    SmartExtract => ("Умная распаковка (без вложенных «Папка\\Папка»)", "Smart Extract (no Folder\\Folder nesting)"),
    SelectedOnly => ("Только выбранное ({0})", "Selected only ({0})"),
    WholeArchive => ("Весь архив", "Whole archive"),
    ThreadsAuto => ("авто", "auto"),
    StartExtract => ("Распаковать", "Extract"),
    ConflictsTitle => ("Файлы уже существуют", "Files already exist"),
    ConflictsText => (
        "В папке назначения уже есть {0} файл(ов) с такими именами. Что сделать?",
        "{0} file(s) with the same names already exist at the destination. What should happen?"
    ),
    ConflictSkip => ("Пропустить", "Skip"),
    ConflictReplace => ("Заменить", "Replace"),
    ConflictKeepBoth => ("Оставить оба", "Keep both"),
    Working => ("Выполняется…", "Working…"),
    CurrentItem => ("Сейчас: {0}", "Now: {0}"),
    DoneExtract => ("Готово: {0} файлов, {1} за {2} с", "Done: {0} files, {1} in {2} s"),
    DoneCreate => ("Создан {0}: {1} → {2} за {3} с", "Created {0}: {1} → {2} in {3} s"),
    SkippedExisting => ("Пропущено существующих: {0}", "Skipped existing: {0}"),
    KeptBoth => ("Сохранено под новыми именами: {0}", "Saved under new names: {0}"),
    BlockedEntries => ("Заблокировано небезопасных записей: {0}", "Unsafe entries blocked: {0}"),
    FailedEntries => ("Ошибок: {0}", "Errors: {0}"),
    ShowDetails => ("Подробности", "Details"),
    OpenFolder => ("Открыть папку", "Open folder"),
    Cancelled => ("Отменено", "Cancelled"),
    CreateTitle => ("Создать архив", "Create archive"),
    CreateFormat => ("Формат", "Format"),
    CreateLevel => ("Уровень сжатия", "Compression level"),
    CreateName => ("Файл архива", "Archive file"),
    AddFiles => ("Добавить файлы…", "Add files…"),
    AddFolder => ("Добавить папку…", "Add folder…"),
    RemoveItem => ("Убрать", "Remove"),
    NothingAdded => ("Добавьте файлы или папки (можно перетащить в окно)", "Add files or folders (you can drop them onto the window)"),
    StartCreate => ("Создать", "Create"),
    FormatZip => ("ZIP (deflate) — открывается везде", "ZIP (deflate) — opens everywhere"),
    FormatZipZstd => ("ZIP (zstd) — быстрее, нужен современный архиватор", "ZIP (zstd) — faster, needs a modern archiver"),
    Format7z => ("7z (LZMA2) — лучшее сжатие", "7z (LZMA2) — best compression"),
    FormatTarZst => ("TAR.ZST — быстро", "TAR.ZST — fast"),
    FormatTarLz4 => ("TAR.LZ4 — очень быстро", "TAR.LZ4 — very fast"),
    FormatTarGz => ("TAR.GZ", "TAR.GZ"),
    FormatTarXz => ("TAR.XZ", "TAR.XZ"),
    FormatPrat => ("Packrat (.prat) — без повторов, шифрование, ремонт", "Packrat (.prat) — dedup, encryption, repair"),
    CreateRecovery => ("Данные восстановления, % (ZIP и .prat)", "Recovery data, % (ZIP and .prat)"),
    CreateRecoveryHint => ("0 — без восстановления. Повреждённый архив чинит команда packrat-cli repair.", "0 = none. A damaged archive is repaired with packrat-cli repair."),
    CreatePratNote => (".prat открывают Packrat и 7-Zip с плагином packrat7z.dll; имена всегда скрыты при пароле.", ".prat opens in Packrat and in 7-Zip with the packrat7z.dll plugin; names are always hidden when there is a password."),
    SettingsTitle => ("Настройки", "Settings"),
    SettingLanguage => ("Язык интерфейса", "Interface language"),
    SettingThreads => ("Потоки для сжатия и распаковки", "Threads for compression and extraction"),
    SettingSmartDefault => ("Умная распаковка по умолчанию", "Smart Extract by default"),
    SettingCheckUpdates => ("Проверять обновления раз в сутки (единственный сетевой запрос)", "Check for updates once a day (the only network request)"),
    Diagnostics => ("Диагностика", "Diagnostics"),
    OpenLogsFolder => ("Открыть папку журналов", "Open logs folder"),
    CopyDiagnostics => ("Скопировать диагностику", "Copy diagnostics"),
    Copied => ("Скопировано в буфер обмена", "Copied to clipboard"),
    InstallSection => ("Установка", "Installation"),
    InstallNow => ("Установить для текущего пользователя", "Install for the current user"),
    Installed => ("Установлено: {0}", "Installed: {0}"),
    AboutText => ("Менеджер архивов для Windows. Лицензия MIT или Apache-2.0.", "Archive manager for Windows. MIT or Apache-2.0 license."),
    UpdateAvailable => ("Доступна версия {0}", "Version {0} is available"),
    UpdateUpToDate => ("Установлена последняя версия", "You have the latest version"),
    UpdateCheck => ("Проверить обновления", "Check for updates"),
    UpdateInstall => ("Обновить и перезапустить", "Update and restart"),
    UpdateDownloading => ("Скачивание…", "Downloading…"),
    UpdateFailed => ("Не удалось обновить: {0}", "Update failed: {0}"),
    UpdateChecking => ("Проверка…", "Checking…"),
    DemoBanner => ("ДЕМО: все данные выдуманные, ничего не читается и не пишется", "DEMO: all data is made up, nothing is read or written"),
    DemoNoWrite => ("В демо-режиме ничего не распаковывается", "Nothing is extracted in demo mode"),
    ErrorGeneric => ("Ошибка: {0}", "Error: {0}"),
    DropToAdd => ("Отпустите, чтобы добавить в архив", "Release to add to an archive"),
    CrashReportFound => ("В прошлый раз Packrat завершился сбоем. Отчёт: {0}", "Packrat crashed last time. Report: {0}"),
    Expand => ("Развернуть всё", "Expand all"),
    Collapse => ("Свернуть всё", "Collapse all"),
    DragTooLarge => ("Для перетаскивания слишком много данных (больше {0}): используйте «Распаковать»", "Too much data to drag out (over {0}): use Extract"),
    EncodingButton => ("Кодировка имён: {0}", "Name encoding: {0}"),
    EncodingTitle => ("Кодировка имён файлов", "File name encoding"),
    EncodingText => (
        "В архиве не указана кодировка имён. Packrat определил её сам ({0}). Если имена выглядят неправильно, выберите другую.",
        "The archive does not say which encoding its names use. Packrat guessed {0}. If the names look wrong, pick another one."
    ),
    EncodingChoose => ("Кодировка", "Encoding"),
    EncodingDetected => ("определена автоматически", "detected automatically"),
    EncodingPreview => ("Так будут выглядеть имена:", "The names will look like this:"),
    EncodingApply => ("Применить", "Apply"),
    PasswordTitle => ("Нужен пароль", "Password required"),
    PasswordText => ("Архив зашифрован. Введите пароль: он нигде не сохраняется.", "The archive is encrypted. Enter the password; it is never stored."),
    PasswordLabel => ("Пароль", "Password"),
    PasswordWrong => ("Пароль не подошёл. Попробуйте ещё раз.", "That password did not work. Try again."),
    PasswordShow => ("Показать", "Show"),
    PasswordEnter => ("Ввести пароль…", "Enter password…"),
    RetryPassword => ("Ввести пароль заново", "Enter the password again"),
    CreatePassword => ("Пароль (по желанию, AES-256)", "Password (optional, AES-256)"),
    CreatePasswordPrat => ("Пароль (по желанию, XChaCha20-Poly1305)", "Password (optional, XChaCha20-Poly1305)"),
    CreateEncryptNames => ("Скрыть и имена файлов (только 7z)", "Hide file names too (7z only)"),
    CreateNoTarPassword => ("TAR не шифруется: выберите ZIP или 7z", "TAR cannot be encrypted: choose ZIP or 7z"),
    WeakEncryption => ("⚠ ZipCrypto — слабое шифрование", "⚠ ZipCrypto is weak encryption"),
    WeakEncryptionHint => (
        "Пароль ZipCrypto можно вскрыть, если известен фрагмент файла. Для новых архивов используйте AES.",
        "A ZipCrypto password can be recovered when part of a file is known. Use AES for new archives."
    ),
    RiskTitle => ("Архив выглядит подозрительно", "This archive looks suspicious"),
    RiskText => (
        "Перед распаковкой найдены признаки архивной бомбы или нехватки места:",
        "Before extracting, signs of an archive bomb or of too little space were found:"
    ),
    RiskContinue => ("Продолжить на свой риск", "Continue at my own risk"),
    RiskHighRatio => ("«{0}» распаковывается примерно в {1} раз больше ({2})", "\"{0}\" expands about {1} times ({2})"),
    RiskHighTotalRatio => ("Архив целиком распаковывается примерно в {0} раз больше ({1})", "The whole archive expands about {0} times ({1})"),
    RiskTotalTooLarge => ("Будет записано {0}: это больше лимита {1}", "{0} would be written: more than the limit of {1}"),
    RiskNotEnoughSpace => ("Нужно {0}, а свободно только {1}", "{0} is needed but only {1} is free"),
    RiskTooManyEntries => ("В архиве {0} записей (лимит {1})", "The archive has {0} entries (limit {1})"),
    RiskOverlap => ("{0} записей делят одни и те же сжатые данные (перекрытие записей)", "{0} entries share the same stored data (overlapping entries)"),
    RiskNesting => ("Архивы вложены друг в друга на {0} уровней (лимит {1})", "Archives are nested {0} levels deep (limit {1})"),
    RiskNestedExpansion => ("Вложенные архивы распакуются ещё минимум в {0}", "Nested archives would expand to at least {0} more"),
    StoppedByLimit => ("Распаковка остановлена по лимиту: {0}", "Extraction stopped by a limit: {0}"),
    PreviewTitle => ("Просмотр", "Preview"),
    PreviewNothing => ("Выберите один файл, чтобы посмотреть его содержимое без распаковки", "Select one file to see its content without extracting"),
    PreviewLoading => ("Чтение…", "Reading…"),
    PreviewTruncated => ("Показано только начало файла", "Only the beginning of the file is shown"),
    PreviewSlow => ("Архив потоковый: чтение до этого файла может быть медленным", "Streaming archive: reaching this file may be slow"),
    PreviewTooFar => ("Просмотр недоступен: {0}", "Preview unavailable: {0}"),
    PreviewImageOpen => ("Открыть крупно", "Open full size"),
    PreviewHex => ("Двоичные данные (шестнадцатеричный вид)", "Binary data (hex view)"),
    PreviewNeedPassword => ("Файл зашифрован", "The file is encrypted"),
    PreviewError => ("Не удалось прочитать: {0}", "Cannot read: {0}"),
    PreviewDimensions => ("{0}×{1} пикселей", "{0}×{1} pixels"),
    MenuExtractHere => ("Распаковать здесь (умно)", "Extract here (smart)"),
    MenuExtractTo => ("Распаковать в папку…", "Extract to folder…"),
    MenuTest => ("Проверить архив", "Test archive"),
    MenuOpen => ("Открыть в Packrat", "Open in Packrat"),
    MenuAdd => ("Добавить в архив…", "Add to archive…"),
    MenuQuickZip => ("В .zip", "To .zip"),
    MenuQuick7z => ("В .7z", "To .7z"),
    MenuQuickTarZst => ("В .tar.zst", "To .tar.zst"),
    VerifyArchive => ("Проверить", "Test"),
    VerifyClean => ("Проверено файлов: {0} ({1}). Повреждений нет.", "Checked {0} files ({1}). No damage found."),
    VerifyDamaged => ("Повреждено файлов: {0} из {1}", "Damaged files: {0} of {1}"),
    VerifySha => ("SHA-256 архива: {0}", "Archive SHA-256: {0}"),
    VerifyRunning => ("Проверка целостности…", "Checking integrity…"),
    RepairButton => ("Починить частично…", "Repair partially…"),
    RepairText => (
        "Архив не открывается обычным способом. Packrat может восстановить список файлов по локальным заголовкам и извлечь всё, что читается; повреждённые файлы сохраняются как .partial.",
        "The archive does not open normally. Packrat can rebuild the file list from the local headers and extract everything that can be read; damaged files are kept as .partial."
    ),
    RecoveredBanner => ("⚠ Архив восстановлен по локальным заголовкам: найдено записей — {0}", "⚠ The archive was rebuilt from local headers: {0} entries found"),
    ExplorerSection => ("Проводник", "Explorer"),
    ExplorerMenu => ("Меню «Packrat ▸» в контекстном меню Проводника", "“Packrat ▸” in the Explorer context menu"),
    ExplorerMenuHint => ("В Windows 11 оно в «Показать дополнительные параметры» (Shift+F10).", "On Windows 11 it is under “Show more options” (Shift+F10)."),
    ClassicMenu => ("Классическое контекстное меню Windows 11 (Packrat виден сразу, без «Показать дополнительные параметры»)", "Classic context menu on Windows 11 (Packrat shows up at once, no “Show more options”)"),
    ClassicMenuHint => ("Меняет меню для всех программ; откат — снять галочку. Применяется после перезапуска Проводника.", "Changes the menu for every program; untick to undo. Takes effect after Explorer restarts."),
    RestartExplorer => ("Перезапустить Проводник", "Restart Explorer"),
    SendToName => ("Packrat — в архив", "Packrat — to archive"),
    SettingOpenAfter => ("После распаковки открывать папку (из Проводника окно закроется само)", "Open the folder after extracting (the window closes by itself when started from Explorer)"),
    SettingDeleteAfter => ("После успешной распаковки удалять архив (в корзину)", "Delete the archive after a clean extraction (to the Recycle Bin)"),
    BatchTitle => ("Распаковка архива {0} из {1}", "Extracting archive {0} of {1}"),
    BatchAllDone => ("Распаковано архивов: {0}", "Archives extracted: {0}"),
    BatchSomeDone => ("Распаковано без замечаний: {0} из {1}", "Extracted cleanly: {0} of {1}"),
    ArchiveDeleted => ("Архив перемещён в корзину", "The archive was moved to the Recycle Bin"),
    ArchiveNotDeleted => ("Архив не удалён: {0}", "The archive was not deleted: {0}"),
    AssocSet => ("Назначить Packrat для архивов (для текущего пользователя)", "Use Packrat for archives (current user)"),
    AssocRestore => ("Вернуть ассоциации как были", "Restore the previous associations"),
    AssocState => ("Назначено: {0}", "Assigned: {0}"),
    AssocNone => ("Ассоциации не назначены", "No associations assigned"),
    AssocHint => (
        "Windows 10/11 может попросить подтвердить выбор в «Параметры → Приложения по умолчанию».",
        "Windows 10/11 may ask you to confirm the choice in Settings → Default apps."
    ),
    AssocOpenSettings => ("Открыть параметры Windows", "Open Windows settings"),
    AdminRetry => ("Распаковать от администратора", "Extract as administrator"),
    AdminHint => (
        "Нет доступа к папке назначения. Можно повторить распаковку в отдельном окне с правами администратора (один запрос UAC).",
        "The destination folder is not writable. You can repeat the extraction in a separate window with administrator rights (one UAC prompt)."
    ),
    AdminWindowTitle => ("Packrat (администратор)", "Packrat (administrator)"),
    ContextMenuHint => ("Меню «Packrat ▸» — в контекстном меню (Windows 11: «Показать дополнительные параметры»).", "The “Packrat ▸” menu is in the context menu (Windows 11: “Show more options”)."),
    UninstallConfirm => ("Удалить Packrat из", "Uninstall Packrat from"),
    Uninstalled => ("Packrat удалён.", "Packrat has been uninstalled."),
}

pub fn t(key: Key) -> &'static str {
    key.text(lang())
}

/// Translated text with `{0}`, `{1}`, … replaced by `args`.
pub fn tf(key: Key, args: &[&str]) -> String {
    let mut s = t(key).to_owned();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), a);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(s: &str) -> Vec<String> {
        let mut v: Vec<String> = s
            .match_indices('{')
            .filter_map(|(i, _)| s[i..].find('}').map(|j| s[i..=i + j].to_owned()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn every_key_has_both_languages_with_matching_placeholders() {
        for k in Key::ALL {
            let (ru, en) = (k.text(Lang::Ru), k.text(Lang::En));
            assert!(!ru.is_empty() && !en.is_empty(), "{k:?} is empty");
            assert_eq!(placeholders(ru), placeholders(en), "{k:?}: placeholders differ");
        }
    }

    #[test]
    fn formatting_fills_positions() {
        set_lang(Lang::En);
        assert_eq!(tf(Key::SkippedExisting, &["5"]), "Skipped existing: 5");
        set_lang(Lang::Ru);
        assert_eq!(tf(Key::SkippedExisting, &["5"]), "Пропущено существующих: 5");
    }
}
