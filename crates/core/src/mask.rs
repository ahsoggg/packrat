//! File name masks (`*.log`, `src/**`, `node_modules`) for choosing what goes into an archive or comes out of one.
//!
//! Wildcards: `*` any run of characters (separators included, as in 7-Zip), `?` one character. A mask without a
//! `/` is tried against every folder and file name on the path, so `node_modules` leaves out the whole folder and
//! `*.log` finds logs at any depth. A mask with a `/` is tried against the path from the archive root and against
//! every leading part of it. Case is ignored.

/// Include and exclude masks. Empty `include` means everything.
#[derive(Clone, Debug, Default)]
pub struct Masks {
    include: Vec<Mask>,
    exclude: Vec<Mask>,
}

#[derive(Clone, Debug)]
struct Mask {
    pattern: Vec<char>,
    anchored: bool,
}

impl Mask {
    fn new(text: &str) -> Mask {
        let text = text.replace('\\', "/");
        let text = text.trim_start_matches("./").trim_end_matches('/');
        Mask {
            anchored: text.contains('/'),
            pattern: text.to_lowercase().chars().collect(),
        }
    }

    fn matches(&self, path: &str) -> bool {
        let lower = path.to_lowercase();
        let lower = lower.trim_end_matches('/');
        if self.anchored {
            // the whole path or any leading part of it (a folder mask covers what is inside)
            let mut end = 0;
            for part in lower.split('/') {
                end += part.len();
                if wild(&self.pattern, &lower[..end].chars().collect::<Vec<_>>()) {
                    return true;
                }
                end += 1;
            }
            false
        } else {
            lower
                .split('/')
                .any(|part| wild(&self.pattern, &part.chars().collect::<Vec<_>>()))
        }
    }
}

/// Classic iterative wildcard match with backtracking to the last `*`.
fn wild(p: &[char], s: &[char]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

impl Masks {
    pub fn new() -> Masks {
        Masks::default()
    }

    pub fn include(&mut self, mask: &str) {
        self.include.push(Mask::new(mask));
    }

    pub fn exclude(&mut self, mask: &str) {
        self.exclude.push(Mask::new(mask));
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    pub fn has_include(&self) -> bool {
        !self.include.is_empty()
    }

    pub fn excluded(&self, path: &str) -> bool {
        self.exclude.iter().any(|m| m.matches(path))
    }

    /// A file (or folder) passes when it is not excluded and, if there are include masks, matches one of them.
    pub fn allows(&self, path: &str) -> bool {
        !self.excluded(path) && (self.include.is_empty() || self.include.iter().any(|m| m.matches(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(inc: &[&str], exc: &[&str]) -> Masks {
        let mut x = Masks::new();
        inc.iter().for_each(|s| x.include(s));
        exc.iter().for_each(|s| x.exclude(s));
        x
    }

    #[test]
    fn wildcards() {
        let w = |p: &str, s: &str| wild(&p.chars().collect::<Vec<_>>(), &s.chars().collect::<Vec<_>>());
        assert!(w("*.log", "a.log"));
        assert!(w("a?c", "abc"));
        assert!(!w("a?c", "ac"));
        assert!(w("*a*b*", "xxaxxbxx"));
        assert!(!w("*.log", "a.logx"));
        assert!(w("*", ""));
    }

    #[test]
    fn plain_mask_matches_any_depth_and_whole_folders() {
        let x = m(&[], &["*.LOG", "node_modules"]);
        assert!(x.excluded("a/b/c.log"));
        assert!(x.excluded("app/node_modules/pkg/index.js"));
        assert!(!x.excluded("app/src/index.js"));
        assert!(x.allows("app/src/index.js"));
    }

    #[test]
    fn anchored_mask_covers_what_is_inside() {
        let x = m(&["src/*"], &["src/gen"]);
        assert!(x.allows("src/a.rs"));
        assert!(x.allows("src/deep/b.rs"));
        assert!(!x.allows("src/gen/c.rs"));
        assert!(!x.allows("docs/a.rs"));
    }

    #[test]
    fn include_with_exclude_and_backslashes() {
        let x = m(&["*.rs", "*.toml"], &["target"]);
        assert!(x.allows("crates\\core\\lib.rs"));
        assert!(!x.allows("target/debug/x.rs"));
        assert!(!x.allows("README.md"));
    }
}
