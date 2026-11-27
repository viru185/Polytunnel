//! Hidden signature shown by `--author`.
//!
//! Self-contained: the standard library only (plus `windows-sys` / `libc` for the few console
//! calls Python makes through `ctypes` and `msvcrt`), uses nothing from the program, so this one
//! file is copied unchanged into every program. It is a line-by-line port of the Python
//! `author.py`; keep the two identical. Wire it before argument parsing, configuration and
//! logging:
//!
//! ```ignore
//! if std::env::args().any(|arg| arg == "--author") {
//!     std::process::exit(author::show(None));
//! }
//! ```
//!
//! In --help it appears only as a hint ("--author   who built this"); never in a README or a log.
//! In a console it plays a short animation (any key skips it); redirected, piped or with
//! NO_COLOR it prints a plain ASCII card.

use std::collections::HashMap;
use std::env;
use std::io::{self, IsTerminal, Stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const NAME: &str = "Viren Hirpara";
pub const QUOTE: [&str; 3] = [
    "My soldiers, rage!",
    "My soldiers, scream!",
    "My soldiers, fight!",
];
pub const BY: &str = "Erwin Smith";

/// An RGB colour (a tuple of three ints in Python).
pub type Rgb = (u8, u8, u8);

// crimson -> ember -> gold
pub const EMBER: [Rgb; 4] = [
    (0x5B, 0x0E, 0x14),
    (0xB3, 0x12, 0x2E),
    (0xFF, 0x5A, 0x1F),
    (0xFF, 0xC8, 0x57),
];
pub const WORD_COLORS: [Rgb; 3] = [(255, 122, 51), (255, 72, 48), (255, 200, 87)]; // rage, scream, fight: hotter
pub const TEXT: Rgb = (226, 226, 226);
pub const SOFT: Rgb = (150, 150, 150);
pub const FAINT: Rgb = (96, 96, 96);
pub const HEAD: Rgb = (255, 238, 204);
pub const WHITE: Rgb = (255, 255, 255);

pub const PAD: usize = 4; // spaces inside the frame on each side
pub const RESET: &str = "\x1b[0m";

// timeline, seconds
pub const T_BORDER: f64 = 0.45;
pub const T_NAME: f64 = 0.40;
pub const NAME_LEN: f64 = 0.85;
pub const NAME_STAGGER: f64 = 0.15;
pub const T_QUOTE: f64 = 1.55;
pub const Q_STEP: f64 = 0.55;
pub const CHAR: f64 = 0.016;
pub const SLAM: f64 = 0.27;
pub const FLASH: f64 = 0.07;
pub const T_BY: f64 = 3.15;
pub const T_SIG: f64 = 3.35;
pub const SIG_CHAR: f64 = 0.012;
pub const END: f64 = 3.95;

// 5x5 block letters ("#" = on); I is narrower
pub const FONT: &[(char, [&str; 5])] = &[
    ('A', [" ### ", "#   #", "#####", "#   #", "#   #"]),
    ('B', ["#### ", "#   #", "#### ", "#   #", "#### "]),
    ('C', [" ####", "#    ", "#    ", "#    ", " ####"]),
    ('D', ["#### ", "#   #", "#   #", "#   #", "#### "]),
    ('E', ["#####", "#    ", "#### ", "#    ", "#####"]),
    ('F', ["#####", "#    ", "#### ", "#    ", "#    "]),
    ('G', [" ####", "#    ", "#  ##", "#   #", " ####"]),
    ('H', ["#   #", "#   #", "#####", "#   #", "#   #"]),
    ('I', ["###", " # ", " # ", " # ", "###"]),
    ('J', ["  ###", "    #", "    #", "#   #", " ### "]),
    ('K', ["#   #", "#  # ", "###  ", "#  # ", "#   #"]),
    ('L', ["#    ", "#    ", "#    ", "#    ", "#####"]),
    ('M', ["#   #", "## ##", "# # #", "#   #", "#   #"]),
    ('N', ["#   #", "##  #", "# # #", "#  ##", "#   #"]),
    ('O', [" ### ", "#   #", "#   #", "#   #", " ### "]),
    ('P', ["#### ", "#   #", "#### ", "#    ", "#    "]),
    ('Q', [" ### ", "#   #", "# # #", "#  # ", " ## #"]),
    ('R', ["#### ", "#   #", "#### ", "#  # ", "#   #"]),
    ('S', [" ####", "#    ", " ### ", "    #", "#### "]),
    ('T', ["#####", "  #  ", "  #  ", "  #  ", "  #  "]),
    ('U', ["#   #", "#   #", "#   #", "#   #", " ### "]),
    ('V', ["#   #", "#   #", "#   #", " # # ", "  #  "]),
    ('W', ["#   #", "#   #", "# # #", "## ##", "#   #"]),
    ('X', ["#   #", " # # ", "  #  ", " # # ", "#   #"]),
    ('Y', ["#   #", " # # ", "  #  ", "  #  ", "  #  "]),
    ('Z', ["#####", "   # ", "  #  ", " #   ", "#####"]),
    ('-', ["     ", "     ", " ### ", "     ", "     "]),
    ('.', ["  ", "  ", "  ", "  ", "# "]),
    (' ', ["   ", "   ", "   ", "   ", "   "]),
];

// ------------------------------------------------------------------------------ python stand-ins
/// Python's `len()` of a str: it counts characters (code points), not UTF-8 bytes.
fn len(text: &str) -> usize {
    text.chars().count()
}

/// `date.today().year`, from the system clock (in UTC: std has no time zones).
fn this_year() -> i64 {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / 86_400);
    // Howard Hinnant's civil_from_days: days since 1970-01-01 -> civil year
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of the 400-year era
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // year of the era
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of a year that starts on March 1
    let mp = (5 * doy + 2) / 153; // month, counted from March
    let year = yoe + era * 400;
    if mp < 10 { year } else { year + 1 } // January and February close that March year
}

/// A tiny seeded random generator (splitmix64), standing in for Python's `random.Random`.
/// Only the animation's noise uses it: the finished card has no randomness.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// `random.Random(seed)`
    pub fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    /// `random.Random()`: seeded from the clock and the process id.
    fn from_clock() -> Rng {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos() as u64);
        Rng::new(nanos ^ u64::from(std::process::id()))
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `random()`: a float in [0, 1), from 53 random bits like Python's.
    pub fn random(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1_u64 << 53) as f64
    }

    /// `choice(seq)`: one character of `seq` (an empty `seq` panics, like Python's IndexError).
    pub fn choice(&mut self, seq: &str) -> char {
        let chars: Vec<char> = seq.chars().collect();
        chars[(self.next_u64() % chars.len() as u64) as usize]
    }
}

// ------------------------------------------------------------------------------ plain card
pub fn plain_card() -> String {
    plain_card_for_year(this_year())
}

fn plain_card_for_year(year: i64) -> String {
    let by = format!("- {BY}");
    let spaced: Vec<String> = NAME.to_uppercase().chars().map(String::from).collect();
    [
        String::new(),
        format!("  {}", spaced.join(" ")),
        String::new(),
        format!("  \"{}", QUOTE[0]),
        format!("   {}", QUOTE[1]),
        format!("   {}\"", QUOTE[2]),
        format!("{by:>width$}", width = len(QUOTE[2]) + 5),
        String::new(),
        format!("  crafted by {NAME}  (c) {year}"),
        String::new(),
        String::new(),
    ]
    .join("\n")
}

// ------------------------------------------------------------------------------ letters
/// `FONT.get(ch, FONT[" "])`
fn font_glyph(ch: char) -> &'static [&'static str; 5] {
    let get = |key: char| FONT.iter().find(|(c, _)| *c == key).map(|(_, rows)| rows);
    get(ch).or_else(|| get(' ')).expect("FONT has a space")
}

pub fn pixels(word: &str) -> Vec<String> {
    let mut rows = vec![String::new(); 5];
    for (n, ch) in word.to_uppercase().chars().enumerate() {
        let glyph = font_glyph(ch);
        for (row, line) in rows.iter_mut().zip(glyph) {
            row.push_str(if n == 0 { "" } else { " " });
            row.push_str(line);
        }
    }
    rows
}

/// Two columns per pixel: square pixels in a normal console font.
pub fn big(word: &str) -> Vec<String> {
    pixels(word)
        .iter()
        .map(|row| {
            row.chars()
                .map(|p| if p == '#' { "██" } else { "  " })
                .collect()
        })
        .collect()
}

/// Half blocks: two pixel rows per text row.
pub fn compact(word: &str) -> Vec<String> {
    let mut px = pixels(word);
    px.push(" ".repeat(len(&px[0])));
    let mut out = Vec::new();
    for y in [0, 2, 4] {
        out.push(
            px[y]
                .chars()
                .zip(px[y + 1].chars())
                .map(|(a, b)| {
                    if a == '#' && b == '#' {
                        '█'
                    } else if a == '#' {
                        '▀'
                    } else if b == '#' {
                        '▄'
                    } else {
                        ' '
                    }
                })
                .collect(),
        );
    }
    out
}

// ------------------------------------------------------------------------------ colour
pub fn mix(t: f64) -> Rgb {
    let t = t.clamp(0.0, 1.0) * (EMBER.len() - 1) as f64;
    let i = (t as usize).min(EMBER.len() - 2); // `as usize` truncates like int()
    let f = t - i as f64;
    let (a, b) = (EMBER[i], EMBER[i + 1]);
    // round_ties_even is Python's round(): halves go to the even neighbour
    let channel =
        |a: u8, b: u8| (f64::from(a) + (f64::from(b) - f64::from(a)) * f).round_ties_even() as u8;
    (channel(a.0, b.0), channel(a.1, b.1), channel(a.2, b.2))
}

pub fn dim(rgb: Rgb, k: f64) -> Rgb {
    let scale = |c: u8| (f64::from(c) * k).round_ties_even() as u8;
    (scale(rgb.0), scale(rgb.1), scale(rgb.2))
}

pub fn sgr(rgb: Rgb, bold: bool, italic: bool) -> String {
    let flags = String::from(if bold { "1;" } else { "" }) + if italic { "3;" } else { "" };
    format!("\x1b[0;{flags}38;2;{};{};{}m", rgb.0, rgb.1, rgb.2)
}

// ------------------------------------------------------------------------------ the card
/// What a body row of the card shows.
#[derive(Clone, Copy)]
enum Row {
    Blank,
    Name(usize, usize), // (word, y): pixel row y of the name's word-th word
    Quote(usize),
    By,
    Rule,
    Sig,
}

/// The signature card at any moment `t` of the animation (`t >= END`: finished).
pub struct Card {
    rng: Rng,
    words: Vec<Vec<String>>,
    word_h: usize,
    quote: [(&'static str, String, &'static str, &'static str); 3],
    quote_w: usize,
    by: String,
    sig: (&'static str, &'static str, String),
    sig_w: usize,
    inner: usize,
    qx: usize,
    rows: Vec<Row>,
    pub width: usize,
    pub height: usize,
    border: HashMap<(usize, usize), (usize, String)>,
}

impl Card {
    pub fn new(render: fn(&str) -> Vec<String>, rng: Rng) -> Card {
        let words: Vec<Vec<String>> = NAME.split_whitespace().map(render).collect();
        let word_h = words[0].len();
        let year = this_year();
        // (lead, typed part, last word, tail): the words themselves are never changed
        let quote = [
            ("“", QUOTE[0], ""),
            (" ", QUOTE[1], ""),
            (" ", QUOTE[2], "”"),
        ]
        .map(|(lead, line, tail)| {
            let (head, word) = line.rsplit_once(' ').expect("each QUOTE line has a space");
            (lead, format!("{head} "), word, tail)
        });
        let quote_w = quote
            .iter()
            .map(|(lead, typed, word, tail)| len(lead) + len(typed) + len(word) + len(tail))
            .max()
            .unwrap_or(0);
        let by = format!("— {BY}");
        let sig = ("crafted by ", NAME, format!("  ·  © {year}"));
        let sig_w = len(sig.0) + len(sig.1) + len(&sig.2);
        let name_w = words.iter().map(|rows| len(&rows[0])).max().unwrap_or(0);
        let inner = name_w.max(quote_w + 8).max(sig_w) + 2 * PAD;
        let qx = (inner - quote_w) / 2;

        let mut rows = vec![Row::Blank];
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                rows.push(Row::Blank);
            }
            rows.extend((0..word.len()).map(|y| Row::Name(i, y)));
        }
        rows.push(Row::Blank);
        rows.extend((0..3).map(Row::Quote));
        rows.extend([Row::By, Row::Blank]);
        rows.extend([Row::Rule, Row::Sig, Row::Blank]);
        let mut card = Card {
            rng,
            words,
            word_h,
            quote,
            quote_w,
            by,
            sig,
            sig_w,
            inner,
            qx,
            width: inner + 2,
            height: rows.len() + 2,
            rows,
            border: HashMap::new(),
        };
        card.border = card.border_cells();
        card
    }

    // -- frame
    /// Each border cell's (index clockwise from the top-left corner, coloured text).
    fn border_cells(&self) -> HashMap<(usize, usize), (usize, String)> {
        let (w, h) = (self.width, self.height);
        let mut cells = HashMap::new();
        for x in 0..w {
            let top = if x == 0 {
                '╭'
            } else if x == w - 1 {
                '╮'
            } else {
                '─'
            };
            let bottom = if x == 0 {
                '╰'
            } else if x == w - 1 {
                '╯'
            } else {
                '─'
            };
            cells.insert((x, 0), (x, top));
            cells.insert((x, h - 1), (w + (h - 2) + (w - 1 - x), bottom));
        }
        for y in 1..h - 1 {
            cells.insert((w - 1, y), (w + y - 1, '│'));
            cells.insert((0, y), (2 * w + (h - 2) + (h - 2 - y), '│'));
        }
        cells
            .into_iter()
            .map(|(pos, (index, ch))| {
                let shade =
                    0.85 * pos.0 as f64 / (w - 1) as f64 + 0.15 * pos.1 as f64 / (h - 1) as f64;
                let color = sgr(dim(mix(shade), 0.8), false, false);
                (pos, (index, format!("{color}{ch}")))
            })
            .collect()
    }

    fn cell(&self, x: usize, y: usize, shown: usize) -> &str {
        let (index, text) = &self.border[&(x, y)];
        if *index < shown { text } else { " " }
    }

    // -- rows
    fn name(&mut self, t: f64, word: usize, y: usize) -> String {
        let row = &self.words[word][y];
        let w = len(row);
        let x0 = (self.inner - w) / 2;
        let start = T_NAME + word as f64 * NAME_STAGGER;
        if t < start - 0.12 {
            return " ".repeat(self.inner);
        }
        let sweep = (t - start) / NAME_LEN * (w + 10) as f64 - 5.0;
        let mut out = " ".repeat(x0);
        for (x, ch) in row.chars().enumerate() {
            let x = x as f64;
            if x < sweep - 2.0 {
                if ch == ' ' {
                    out.push(' ');
                } else {
                    let shade = 0.85 * x / w.saturating_sub(1).max(1) as f64
                        + 0.15 * y as f64 / self.word_h.saturating_sub(1).max(1) as f64;
                    out += &(sgr(mix(0.15 + 0.85 * shade), true, false) + &ch.to_string());
                }
            } else if x <= sweep + 1.0 {
                // the bright decoding edge
                if ch != ' ' {
                    out += &(sgr(HEAD, true, false) + &ch.to_string());
                } else {
                    out += &(sgr(dim(EMBER[1], 0.7), false, false) + "░");
                }
            } else if ch != ' ' {
                let noise = self.rng.choice("▒▓█");
                let k = 0.35 + 0.35 * self.rng.random();
                out += &(sgr(dim(EMBER[1], k), false, false) + &noise.to_string());
            } else if self.rng.random() < 0.18 {
                let color = sgr(dim(EMBER[0], 0.9), false, false);
                out += &(color + &self.rng.choice("░▒").to_string());
            } else {
                out.push(' ');
            }
        }
        out += &" ".repeat(self.inner - x0 - w);
        out
    }

    fn quote(&self, t: f64, i: usize) -> String {
        let &(lead, ref typed, word, tail) = &self.quote[i];
        let start = T_QUOTE + i as f64 * Q_STEP;
        if t < start {
            return " ".repeat(self.inner);
        }
        let n = len(typed).min(((t - start) / CHAR) as usize);
        let typed: String = typed.chars().take(n).collect(); // typed[:n]
        let mut parts = " ".repeat(self.qx);
        parts += &(sgr(EMBER[3], true, false) + lead);
        parts += &(sgr(TEXT, false, false) + &typed);
        let mut used = len(lead) + n;
        let since = t - (start + SLAM);
        if since >= 0.0 {
            let flashes: &[f64] = if i == 2 { &[0.0, 2.0 * FLASH] } else { &[0.0] };
            let white = flashes.iter().any(|&f| (f..f + FLASH).contains(&since));
            let color = if white { WHITE } else { WORD_COLORS[i] };
            parts += &(sgr(color, true, false) + word);
            parts += &(sgr(EMBER[3], true, false) + tail);
            used += len(word) + len(tail);
        }
        parts += &" ".repeat(self.inner - self.qx - used);
        parts
    }

    fn by(&self, t: f64) -> String {
        if t < T_BY {
            return " ".repeat(self.inner);
        }
        let x = self.qx + self.quote_w - len(&self.by);
        let color = if t < T_BY + 0.08 { FAINT } else { SOFT };
        " ".repeat(x)
            + &sgr(color, false, true)
            + &self.by
            + &" ".repeat(self.inner - x - len(&self.by))
    }

    fn rule(&self, t: f64) -> String {
        if t < T_SIG {
            return " ".repeat(self.inner);
        }
        let w = 26;
        let x0 = (self.inner - w) / 2;
        let line: String = (0..w)
            .map(|x| sgr(dim(mix(x as f64 / (w - 1) as f64), 0.55), false, false) + "─")
            .collect();
        " ".repeat(x0) + &line + &" ".repeat(self.inner - x0 - w)
    }

    fn sig(&self, t: f64) -> String {
        if t < T_SIG {
            return " ".repeat(self.inner);
        }
        let n = ((t - T_SIG) / SIG_CHAR) as usize;
        let x0 = (self.inner - self.sig_w) / 2;
        let (before, name, after) = (self.sig.0, self.sig.1, self.sig.2.as_str());
        let mut out = " ".repeat(x0);
        let mut shown = 0;
        for (k, ch) in format!("{before}{name}{after}").chars().enumerate() {
            if k >= n {
                break;
            }
            if (len(before)..len(before) + len(name)).contains(&k) {
                let j = k - len(before);
                let color = mix(0.35 + 0.65 * j as f64 / len(name).saturating_sub(1).max(1) as f64);
                out += &(sgr(color, true, false) + &ch.to_string());
            } else {
                out += &(sgr(SOFT, false, false) + &ch.to_string());
            }
            shown += 1;
        }
        out += &" ".repeat(self.inner - x0 - shown);
        out
    }

    pub fn lines(&mut self, t: f64) -> Vec<String> {
        let (w, h) = (self.width, self.height);
        let shown = (self.border.len() as f64 * (t / T_BORDER).min(1.0)) as usize;
        let mut out = vec![(0..w).map(|x| self.cell(x, 0, shown)).collect::<String>() + RESET];
        // a copy of the (small) row list, so the row painters may borrow self mutably (the rng)
        for (y, row) in (1..).zip(self.rows.clone()) {
            let body = match row {
                Row::Blank => " ".repeat(self.inner),
                Row::Name(word, word_y) => self.name(t, word, word_y),
                Row::Quote(i) => self.quote(t, i),
                Row::By => self.by(t),
                Row::Rule => self.rule(t),
                Row::Sig => self.sig(t),
            };
            out.push(format!(
                "{}{body}{}{RESET}",
                self.cell(0, y, shown),
                self.cell(w - 1, y, shown)
            ));
        }
        out.push(
            (0..w)
                .map(|x| self.cell(x, h - 1, shown))
                .collect::<String>()
                + RESET,
        );
        out
    }
}

// ------------------------------------------------------------------------------ console
/// True when ANSI colour/cursor sequences work on this stream (switches them on in
/// Windows consoles).
fn vt_console(stream: &Stdout) -> bool {
    if env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        || env::var_os("TERM").is_some_and(|value| value == "dumb")
    {
        return false;
    }
    if !stream.is_terminal() {
        return false;
    }
    // Python also checks here that the stream's encoding can write "█░▒▓╭─│“”—·©". Rust needs
    // no such check: it writes UTF-16 to Windows consoles and UTF-8 everywhere else.
    #[cfg(not(windows))]
    {
        true
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::{
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, SetConsoleMode,
        };
        let handle = stream.as_raw_handle(); // msvcrt.get_osfhandle(stream.fileno())
        let mut mode = 0;
        // SAFETY: `handle` is stdout's own handle and `mode` a live u32 to write into.
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        // SAFETY: the same handle; this only adds one flag to the mode it already has.
        unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 }
    }
}

fn key_pressed() -> bool {
    #[cfg(not(windows))]
    {
        false
    }
    #[cfg(windows)]
    {
        // msvcrt.kbhit and msvcrt.getwch are these two C runtime functions
        unsafe extern "C" {
            fn _kbhit() -> i32;
            fn _getwch() -> u16;
        }
        let mut hit = false;
        // SAFETY: _kbhit takes no arguments and only peeks at the console's input buffer.
        while unsafe { _kbhit() } != 0 {
            // SAFETY: no arguments; a key is waiting, so this reads it without blocking.
            unsafe { _getwch() };
            hit = true;
        }
        hit
    }
}

/// `shutil.get_terminal_size(fallback)`: COLUMNS and LINES when they hold positive integers,
/// else the size of the console window on stdout, else `fallback`.
fn terminal_size(fallback: (usize, usize)) -> (usize, usize) {
    let from_env = |name: &str| {
        env::var(name)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0)
    };
    let mut columns = from_env("COLUMNS");
    let mut lines = from_env("LINES");
    // only query if necessary
    if columns == 0 || lines == 0 {
        let size = os_terminal_size().unwrap_or(fallback);
        if columns == 0 {
            columns = if size.0 > 0 { size.0 } else { fallback.0 };
        }
        if lines == 0 {
            lines = if size.1 > 0 { size.1 } else { fallback.1 };
        }
    }
    (columns, lines)
}

/// `os.get_terminal_size(1)` on Windows: the visible window of the console on stdout.
#[cfg(windows)]
fn os_terminal_size() -> Option<(usize, usize)> {
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: GetStdHandle has no preconditions (a bad handle just makes the next call fail),
    // and `info` is a live struct of the right type to write into.
    if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) } == 0 {
        return None;
    }
    let window = info.srWindow;
    let columns = i32::from(window.Right) - i32::from(window.Left) + 1;
    let lines = i32::from(window.Bottom) - i32::from(window.Top) + 1;
    Some((
        usize::try_from(columns).unwrap_or(0),
        usize::try_from(lines).unwrap_or(0),
    ))
}

/// `os.get_terminal_size(1)` on Unix: the TIOCGWINSZ ioctl on stdout.
#[cfg(unix)]
fn os_terminal_size() -> Option<(usize, usize)> {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, and `size` is one.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } != 0 {
        return None;
    }
    Some((usize::from(size.ws_col), usize::from(size.ws_row)))
}

#[cfg(not(any(windows, unix)))]
fn os_terminal_size() -> Option<(usize, usize)> {
    None
}

fn choose_card(columns: usize, rows: usize) -> Option<Card> {
    let rng = Rng::from_clock();
    for render in [big, compact] {
        let card = Card::new(render, rng.clone());
        if card.width < columns && card.height < rows {
            return Some(card);
        }
    }
    None
}

/// Repaints rows of a block reserved below the cursor. Only relative cursor moves (up,
/// down, carriage return) are used: every terminal and ConPTY handles them the same way.
struct Screen<'a> {
    stream: &'a mut dyn Write,
    height: usize,
    row: usize,
}

impl<'a> Screen<'a> {
    fn new(stream: &'a mut dyn Write, height: usize) -> io::Result<Screen<'a>> {
        // hide the cursor, make room
        stream.write_all(format!("\r\x1b[?25l{}", "\n".repeat(height)).as_bytes())?;
        // the cursor sits on the line below the block
        Ok(Screen {
            stream,
            height,
            row: height,
        })
    }

    fn paint(&mut self, frame: &[String], previous: &[String]) -> io::Result<()> {
        let mut out = String::new();
        for (i, (line, before)) in frame.iter().zip(previous).enumerate() {
            if line == before {
                continue;
            }
            if i < self.row {
                out += &format!("\x1b[{}A", self.row - i);
            } else if i > self.row {
                out += &format!("\x1b[{}B", i - self.row);
            }
            out += "\r";
            out += line;
            self.row = i;
        }
        if !out.is_empty() {
            self.stream.write_all(out.as_bytes())?;
            self.stream.flush()?;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        let down = self.height - self.row;
        let down = if down > 0 {
            format!("\x1b[{down}B")
        } else {
            String::new()
        };
        self.stream
            .write_all(format!("{down}\r{RESET}\x1b[?25h\n").as_bytes())?;
        self.stream.flush()
    }
}

/// Set by the Ctrl+C handler while the animation plays.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Turns Ctrl+C into the `INTERRUPTED` flag while the animation plays: Python's
/// `except KeyboardInterrupt`. The usual Ctrl+C behaviour comes back when this is dropped.
struct CtrlC {
    #[cfg(unix)]
    previous: libc::sighandler_t,
}

impl CtrlC {
    fn catch() -> CtrlC {
        INTERRUPTED.store(false, Ordering::SeqCst);
        #[cfg(windows)]
        {
            use windows_sys::Win32::{Foundation::TRUE, System::Console::SetConsoleCtrlHandler};
            // SAFETY: `on_ctrl_event` is a plain function, valid for the life of the program.
            unsafe { SetConsoleCtrlHandler(Some(on_ctrl_event), TRUE) };
            CtrlC {}
        }
        #[cfg(unix)]
        {
            let handler = on_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
            let previous = unsafe { libc::signal(libc::SIGINT, handler) };
            CtrlC { previous }
        }
        #[cfg(not(any(windows, unix)))]
        {
            CtrlC {}
        }
    }

    fn pressed(&self) -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }
}

impl Drop for CtrlC {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::{Foundation::FALSE, System::Console::SetConsoleCtrlHandler};
            // SAFETY: removes the very handler that `catch` added.
            unsafe { SetConsoleCtrlHandler(Some(on_ctrl_event), FALSE) };
        }
        #[cfg(unix)]
        {
            if self.previous != libc::SIG_ERR {
                // SAFETY: puts back the handler that was there before `catch`.
                unsafe { libc::signal(libc::SIGINT, self.previous) };
            }
        }
    }
}

/// Console control handler (it runs on its own thread): claims Ctrl+C and Ctrl+Break.
#[cfg(windows)]
extern "system" fn on_ctrl_event(kind: u32) -> windows_sys::core::BOOL {
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT {
        INTERRUPTED.store(true, Ordering::SeqCst);
        TRUE
    } else {
        FALSE
    }
}

#[cfg(unix)]
extern "C" fn on_sigint(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn play(card: &mut Card, stream: &mut dyn Write) -> io::Result<()> {
    let mut screen = Screen::new(stream, card.height)?;
    let mut previous = vec![String::new(); card.height];
    let begin = Instant::now();
    let ctrl_c = CtrlC::catch(); // try:
    let played = loop {
        if ctrl_c.pressed() {
            // except KeyboardInterrupt:
            break screen.paint(&card.lines(END + 1.0), &previous);
        }
        let t = begin.elapsed().as_secs_f64();
        let done = t >= END || key_pressed();
        let frame = card.lines(if done { END + 1.0 } else { t });
        if let Err(err) = screen.paint(&frame, &previous) {
            break Err(err);
        }
        previous = frame;
        if done {
            break Ok(());
        }
        thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
    };
    let closed = screen.close(); // finally: (Ctrl+C is given back when `ctrl_c` drops)
    played.and(closed)
}

/// Shows the card; returns the exit code (always 0). `None` writes to the real stdout, animated
/// in a console; any other writer is never a console and gets the plain card.
pub fn show(stream: Option<&mut dyn Write>) -> i32 {
    // Python returns early when sys.stdout is None (a windowed build). Not needed here: Rust's
    // stdout quietly discards what is written when the process has no console.
    let mut stdout = io::stdout();
    let (stream, console): (&mut dyn Write, bool) = match stream {
        Some(writer) => (writer, false), // like io.StringIO: isatty() is False
        None => {
            let console = vt_console(&stdout);
            (&mut stdout, console)
        }
    };
    // try:
    if console {
        let (columns, lines) = terminal_size((80, 24));
        if let Some(mut card) = choose_card(columns, lines) {
            if play(&mut card, stream).is_ok() {
                return 0;
            }
            // except Exception: show the cursor again, then fall through to the plain card
            let _ = stream.write_all(format!("{RESET}\x1b[?25h\n").as_bytes());
        }
    }
    let _ = stream.write_all(plain_card().as_bytes());
    let _ = stream.flush();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// `ANSI.sub("", text)` with `ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")`.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find("\x1b[") {
            out.push_str(&rest[..at]);
            let after = &rest[at + 2..];
            let params =
                after.trim_start_matches(|c: char| c.is_ascii_digit() || c == ';' || c == '?');
            match params.chars().next() {
                Some(end) if end.is_ascii_alphabetic() => rest = &params[1..],
                _ => {
                    out.push_str("\x1b["); // not an escape sequence: keep it
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    fn plain_lines(card: &mut Card, t: f64) -> Vec<String> {
        card.lines(t).iter().map(|line| strip_ansi(line)).collect()
    }

    #[test]
    fn plain_card_when_not_a_console() {
        let mut out = Vec::new();
        assert_eq!(show(Some(&mut out)), 0);
        let text = String::from_utf8(out).expect("UTF-8");
        assert!(text.is_ascii());
        assert!(!text.contains('\x1b'));
        for line in QUOTE {
            assert!(text.contains(line));
        }
        assert!(text.contains(NAME) && text.contains(BY));
    }

    #[test]
    fn plain_card_is_byte_for_byte_the_python_one() {
        let expected = concat!(
            "\n",
            "  V I R E N   H I R P A R A\n",
            "\n",
            "  \"My soldiers, rage!\n",
            "   My soldiers, scream!\n",
            "   My soldiers, fight!\"\n",
            "           - Erwin Smith\n",
            "\n",
            "  crafted by Viren Hirpara  (c) 2026\n",
            "\n",
        );
        assert_eq!(plain_card_for_year(2026), expected);
    }

    fn finished_card_is_a_closed_box_with_the_exact_quote(render: fn(&str) -> Vec<String>) {
        let mut card = Card::new(render, Rng::new(1));
        let lines = plain_lines(&mut card, END + 1.0);
        assert_eq!(lines.len(), card.height);
        let widths: HashSet<usize> = lines.iter().map(|line| len(line)).collect();
        assert_eq!(widths, HashSet::from([card.width]));
        assert!(lines[0].starts_with('╭') && lines[lines.len() - 1].ends_with('╯'));
        let body = lines.join("\n");
        for line in QUOTE {
            assert!(body.contains(line));
        }
        assert!(body.contains(&format!("— {BY}")));
        assert!(body.contains(NAME));
    }

    #[test]
    fn finished_big_card_is_a_closed_box_with_the_exact_quote() {
        finished_card_is_a_closed_box_with_the_exact_quote(big);
    }

    #[test]
    fn finished_compact_card_is_a_closed_box_with_the_exact_quote() {
        finished_card_is_a_closed_box_with_the_exact_quote(compact);
    }

    #[test]
    fn every_frame_keeps_the_box_width() {
        let mut card = Card::new(compact, Rng::new(2));
        for step in 0..45 {
            let lines = plain_lines(&mut card, f64::from(step) / 10.0);
            let widths: HashSet<usize> = lines.iter().map(|line| len(line)).collect();
            assert_eq!(widths, HashSet::from([card.width]));
        }
    }
}
