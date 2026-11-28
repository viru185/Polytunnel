//! The tray glyph, drawn at run time at the tray's own size: a monochrome tunnel arch with a
//! status badge at the bottom right.
//!
//! On a 16-unit grid: legs centred at x = 3 and 11, 2 units wide, an arc of radius 4 centred at
//! y = 7, flat feet at y = 14, no light inside. The badge is 6 units across, centred at
//! (13, 13), with a 1-unit transparent knockout ring between it and the arch. The arch's edges
//! are fitted to whole pixels at every size; everything is 4 × 4 supersampled.

/// The badge's shape (badge-shapes differ, so the state does not rest on colour alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Badge {
    /// No badge: the whole arch.
    None,
    /// A ring with a small gap at one of three positions (0, 1, 2), turned while busy.
    Ring(u8),
    /// A filled dot.
    Dot,
    /// A filled square.
    Square,
}

/// The badge's colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Green,
    Amber,
    Red,
}

/// Samples per pixel along each axis.
const SS: u32 = 4;
/// Half the angle of the ring's gap, in radians (35°).
const GAP_HALF: f32 = 35.0 * std::f32::consts::PI / 180.0;

/// The arch's colour: white on a dark taskbar, near-black on a light one.
pub fn ink(light_taskbar: bool) -> [u8; 3] {
    if light_taskbar {
        [0x11, 0x11, 0x11]
    } else {
        [0xFF, 0xFF, 0xFF]
    }
}

/// The badge colours follow the taskbar: pastels on dark, deeper tones on light (3:1 or more
/// against each).
pub fn badge_colour(tone: Tone, light_taskbar: bool) -> [u8; 3] {
    match (tone, light_taskbar) {
        (Tone::Green, false) => [0x5C, 0xD6, 0x9B],
        (Tone::Amber, false) => [0xF4, 0xBE, 0x4F],
        (Tone::Red, false) => [0xFF, 0x6B, 0x6B],
        (Tone::Green, true) => [0x15, 0x80, 0x3D],
        (Tone::Amber, true) => [0xB4, 0x53, 0x09],
        (Tone::Red, true) => [0xC6, 0x28, 0x28],
    }
}

/// The glyph's geometry in pixels for an icon `size` pixels square.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    /// Pixels per unit.
    unit: f32,
    /// The legs' outer edges, the stroke width, the arch's top and its feet.
    left: f32,
    right: f32,
    stroke: f32,
    top: f32,
    foot: f32,
    /// The arc's centre and radii.
    cx: f32,
    cy: f32,
    outer: f32,
    inner: f32,
    /// The badge's centre.
    bx: f32,
    by: f32,
    /// The square badge's centre and half size (its edges on whole pixels), and its corner
    /// radius.
    square_centre: f32,
    square_half: f32,
    square_corner: f32,
}

impl Geometry {
    fn new(size: u32) -> Self {
        let unit = size as f32 / 16.0;
        let snap = |v: f32| (v * unit).round();
        let (left, right) = (snap(2.0), snap(12.0));
        let stroke = snap(2.0).max(1.0);
        let top = snap(2.0);
        let outer = (right - left) / 2.0;
        let (bx, by) = (13.0 * unit, 13.0 * unit);
        // Square edges on whole pixels, centred where the dot is.
        let x0 = snap(13.0 - 2.75);
        let x1 = snap(13.0 + 2.75);
        Geometry {
            unit,
            left,
            right,
            stroke,
            top,
            foot: snap(14.0),
            cx: (left + right) / 2.0,
            cy: top + outer,
            outer,
            inner: outer - stroke,
            bx,
            by,
            square_centre: (x0 + x1) / 2.0,
            square_half: (x1 - x0) / 2.0,
            square_corner: 0.6 * unit,
        }
    }

    fn in_arch(&self, x: f32, y: f32) -> bool {
        if y < self.top || y > self.foot {
            return false;
        }
        if y <= self.cy {
            let d = (x - self.cx).hypot(y - self.cy);
            d >= self.inner && d <= self.outer
        } else {
            (x >= self.left && x <= self.left + self.stroke)
                || (x >= self.right - self.stroke && x <= self.right)
        }
    }

    /// The signed distance (pixels) from the badge's outline: negative inside.
    fn badge_distance(&self, badge: Badge, x: f32, y: f32) -> f32 {
        match badge {
            Badge::None => f32::INFINITY,
            Badge::Ring(_) | Badge::Dot => (x - self.bx).hypot(y - self.by) - 3.0 * self.unit,
            Badge::Square => {
                let (dx, dy) = (x - self.square_centre, y - self.square_centre);
                let r = self.square_corner;
                let qx = dx.abs() - (self.square_half - r);
                let qy = dy.abs() - (self.square_half - r);
                qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - r
            }
        }
    }
}

/// What a point shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Empty,
    Arch,
    Badge,
}

fn part(g: &Geometry, badge: Badge, x: f32, y: f32) -> Part {
    let d = g.badge_distance(badge, x, y);
    if d <= 0.0 {
        if let Badge::Ring(step) = badge {
            // A ring 1.5 units wide with a gap centred at the top, then a third and two
            // thirds of a turn on (clockwise on screen).
            let (dx, dy) = (x - g.bx, y - g.by);
            if dx.hypot(dy) < 1.5 * g.unit {
                return Part::Empty;
            }
            let gap = -std::f32::consts::FRAC_PI_2
                + f32::from(step % 3) * 2.0 * std::f32::consts::FRAC_PI_3;
            let mut off = dy.atan2(dx) - gap;
            off = (off + std::f32::consts::PI).rem_euclid(std::f32::consts::TAU)
                - std::f32::consts::PI;
            if off.abs() < GAP_HALF {
                return Part::Empty;
            }
        }
        return Part::Badge;
    }
    if d <= g.unit {
        return Part::Empty; // the knockout ring
    }
    if g.in_arch(x, y) {
        Part::Arch
    } else {
        Part::Empty
    }
}

/// The glyph as straight (not premultiplied) RGBA, `size` × `size` pixels.
pub fn render(size: u32, light_taskbar: bool, badge: Badge, tone: Tone) -> Vec<u8> {
    let g = Geometry::new(size);
    let ink = ink(light_taskbar);
    let mark = badge_colour(tone, light_taskbar);
    let total = SS * SS;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for py in 0..size {
        for px in 0..size {
            let (mut arch, mut dot) = (0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = px as f32 + (sx as f32 + 0.5) / SS as f32;
                    let y = py as f32 + (sy as f32 + 0.5) / SS as f32;
                    match part(&g, badge, x, y) {
                        Part::Arch => arch += 1,
                        Part::Badge => dot += 1,
                        Part::Empty => {}
                    }
                }
            }
            let cover = arch + dot;
            if cover == 0 {
                continue;
            }
            let i = ((py * size + px) * 4) as usize;
            for c in 0..3 {
                let sum = u32::from(ink[c]) * arch + u32::from(mark[c]) * dot;
                rgba[i + c] = ((sum + cover / 2) / cover) as u8;
            }
            rgba[i + 3] = ((255 * cover + total / 2) / total) as u8;
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: [u32; 7] = [16, 20, 24, 28, 32, 36, 40];

    fn alpha(rgba: &[u8], size: u32, x: u32, y: u32) -> u8 {
        rgba[((y * size + x) * 4 + 3) as usize]
    }

    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * size + x) * 4) as usize;
        [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
    }

    #[test]
    fn the_16_pixel_glyph_is_the_drawing() {
        let g = Geometry::new(16);
        assert_eq!(
            (g.left, g.right, g.stroke, g.top, g.foot),
            (2.0, 12.0, 2.0, 2.0, 14.0)
        );
        assert_eq!((g.cx, g.cy, g.outer, g.inner), (7.0, 7.0, 5.0, 3.0));
        // The legs are whole pixels: fully on at x = 2..4 and 10..12 from y = 8 to 14.
        let idle = render(16, false, Badge::None, Tone::Green);
        for y in 8..14 {
            for x in [2, 3, 10, 11] {
                assert_eq!(pixel(&idle, 16, x, y), [255, 255, 255, 255], "({x}, {y})");
            }
            for x in [0, 1, 4, 5, 9, 12, 13] {
                assert_eq!(alpha(&idle, 16, x, y), 0, "({x}, {y})");
            }
        }
        // Nothing above the arch or below the feet; no light inside.
        for x in 0..16 {
            assert_eq!(alpha(&idle, 16, x, 0), 0);
            assert_eq!(alpha(&idle, 16, x, 1), 0);
            assert_eq!(alpha(&idle, 16, x, 14), 0);
        }
        assert_eq!(alpha(&idle, 16, 7, 10), 0);
    }

    #[test]
    fn glyphs_stay_inside_their_bounds_at_every_tray_size() {
        for size in SIZES {
            let u = size as f32 / 16.0;
            for light in [false, true] {
                for badge in [Badge::None, Badge::Ring(0), Badge::Dot, Badge::Square] {
                    let rgba = render(size, light, badge, Tone::Amber);
                    assert_eq!(rgba.len(), (size * size * 4) as usize);
                    for y in 0..size {
                        for x in 0..size {
                            if alpha(&rgba, size, x, y) == 0 {
                                continue;
                            }
                            // The arch spans x 2..12, y 2..14; the badge x, y 10..16.
                            let (fx, fy) = (x as f32 / u, y as f32 / u);
                            let in_arch = (1.4..12.6).contains(&fx) && (1.4..14.6).contains(&fy);
                            let in_badge = fx >= 9.4 && fy >= 9.4;
                            assert!(
                                in_arch || (badge != Badge::None && in_badge),
                                "{size}px {badge:?}: stray pixel at ({x}, {y})"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_knockout_ring_is_transparent() {
        for size in SIZES {
            let g = Geometry::new(size);
            // On the right leg, just above the badge: inside the knockout ring.
            let (x, y) = (11.0 * g.unit, 9.8 * g.unit);
            assert!(g.in_arch(x, y), "{size}px: the point is on the leg");
            for badge in [Badge::Ring(1), Badge::Dot, Badge::Square] {
                assert_eq!(part(&g, badge, x, y), Part::Empty, "{size}px {badge:?}");
            }
            assert_eq!(part(&g, Badge::None, x, y), Part::Arch);
            // The ring's hole is empty; the dot's and the square's middles are not.
            assert_eq!(part(&g, Badge::Ring(0), g.bx, g.by), Part::Empty);
            assert_eq!(part(&g, Badge::Dot, g.bx, g.by), Part::Badge);
            assert_eq!(part(&g, Badge::Square, g.bx, g.by), Part::Badge);
            // Whole pixels of the leg inside the ring are transparent (at 32 px and up the
            // ring is two pixels wide, so there are some).
            let dot = render(size, false, Badge::Dot, Tone::Green);
            let idle = render(size, false, Badge::None, Tone::Green);
            let mut knocked_out = 0;
            for py in 0..size {
                for px in 0..size {
                    let corners = [(0.01, 0.01), (0.99, 0.01), (0.01, 0.99), (0.99, 0.99)]
                        .map(|(dx, dy)| (px as f32 + dx, py as f32 + dy));
                    if corners.iter().all(|&(cx, cy)| {
                        let d = g.badge_distance(Badge::Dot, cx, cy);
                        g.in_arch(cx, cy) && d > 0.0 && d <= g.unit
                    }) {
                        knocked_out += 1;
                        assert_eq!(alpha(&dot, size, px, py), 0, "{size}px ({px}, {py})");
                        assert_eq!(alpha(&idle, size, px, py), 255, "{size}px ({px}, {py})");
                    }
                }
            }
            if size >= 32 {
                assert!(knocked_out > 0, "{size}px");
            }
        }
    }

    #[test]
    fn badges_take_the_taskbar_colours() {
        for size in SIZES {
            let c = (13 * size / 16).min(size - 1);
            for light in [false, true] {
                let dot = render(size, light, Badge::Dot, Tone::Green);
                let [r, g, b, a] = pixel(&dot, size, c, c);
                assert_eq!(([r, g, b], a), (badge_colour(Tone::Green, light), 255));
                let square = render(size, light, Badge::Square, Tone::Red);
                let [r, g, b, a] = pixel(&square, size, c, c);
                assert_eq!(([r, g, b], a), (badge_colour(Tone::Red, light), 255));
                // The arch itself: a pixel inside the left leg.
                let leg = (3 * size / 16, 10 * size / 16);
                let [r, g, b, _] = pixel(&dot, size, leg.0, leg.1);
                assert_eq!([r, g, b], ink(light));
            }
        }
        assert_eq!(ink(false), [255, 255, 255]);
        assert_eq!(ink(true), [0x11, 0x11, 0x11]);
    }

    #[test]
    fn the_busy_ring_turns() {
        let frames: Vec<_> = (0..3)
            .map(|step| render(24, false, Badge::Ring(step), Tone::Amber))
            .collect();
        assert_ne!(frames[0], frames[1]);
        assert_ne!(frames[1], frames[2]);
        assert_eq!(frames[0], render(24, false, Badge::Ring(3), Tone::Amber));
        // The gap does not move the arch.
        let ink_only = |f: &Vec<u8>| -> Vec<u8> { f[..(24 * 9 * 4)].to_vec() };
        assert_eq!(ink_only(&frames[0]), ink_only(&frames[2]));
    }

    /// Writes every glyph as raw RGBA (`<size>-<theme>-<badge>.rgba`) into the folder named by
    /// `POLYTUNNEL_GLYPH_DIR`, for a look at them. `cargo test -- --ignored dump_glyphs`.
    #[test]
    #[ignore = "writes files for a visual check"]
    fn dump_glyphs() {
        let Some(dir) = std::env::var_os("POLYTUNNEL_GLYPH_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let looks = [
            ("idle", Badge::None, Tone::Green),
            ("busy0", Badge::Ring(0), Tone::Amber),
            ("busy1", Badge::Ring(1), Tone::Amber),
            ("busy2", Badge::Ring(2), Tone::Amber),
            ("connected", Badge::Dot, Tone::Green),
            ("limited", Badge::Dot, Tone::Amber),
            ("blocked", Badge::Square, Tone::Amber),
            ("problem", Badge::Square, Tone::Red),
        ];
        for size in SIZES {
            for (theme, light) in [("dark", false), ("light", true)] {
                for (name, badge, tone) in looks {
                    let path = dir.join(format!("{size}-{theme}-{name}.rgba"));
                    std::fs::write(path, render(size, light, badge, tone)).unwrap();
                }
            }
        }
    }
}
