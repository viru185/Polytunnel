//! Line icons drawn with the painter (the bundled fonts have no icon glyphs). Each icon is
//! designed on a 20 × 20 grid (the same as `design/mockups.html`) and drawn with a constant
//! 1.5-point stroke whatever its size, so 16 and 20 point icons look alike.

use std::f32::consts::{PI, TAU};

use eframe::egui::{
    Color32, CornerRadius, Painter, Pos2, Rect, Shape, Stroke, StrokeKind, Vec2, pos2, vec2,
};

/// The stroke width of every icon, in points.
pub const STROKE: f32 = 1.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    Shield,
    ShieldCheck,
    /// The administrator shield (Windows asks to confirm).
    Uac,
    Log,
    Gear,
    ChevronRight,
    ChevronDown,
    ChevronUp,
    Back,
    Plus,
    More,
    Copy,
    Trash,
    Up,
    Down,
    Close,
    Check,
    Refresh,
    Key,
    Lock,
    Warning,
    Info,
    Error,
    Ok,
    Dot,
    User,
    Rosette,
    Download,
    ArrowDown,
    ArrowUp,
    Eye,
    External,
    Paste,
    Edit,
    Power,
}

/// One stroke of an icon, on the 20 × 20 grid.
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Open(Vec<Pos2>),
    Closed(Vec<Pos2>),
    Circle(Pos2, f32),
    /// A filled dot.
    Dot(Pos2, f32),
    /// An outlined rounded rectangle: top-left, size, corner radius.
    RoundRect(Pos2, Vec2, f32),
}

/// Points along a circle from angle `from` (radians, 0 = right, clockwise on screen) through
/// `sweep`.
pub fn arc(center: Pos2, radius: f32, from: f32, sweep: f32, steps: usize) -> Vec<Pos2> {
    (0..=steps)
        .map(|i| center + radius * Vec2::angled(from + sweep * i as f32 / steps as f32))
        .collect()
}

/// Points along a cubic Bézier curve.
fn cubic(a: Pos2, b: Pos2, c: Pos2, d: Pos2, steps: usize) -> Vec<Pos2> {
    (0..=steps)
        .map(|i| {
            let t = i as f32 / steps as f32;
            let u = 1.0 - t;
            let v = a.to_vec2() * u * u * u
                + b.to_vec2() * 3.0 * u * u * t
                + c.to_vec2() * 3.0 * u * t * t
                + d.to_vec2() * t * t * t;
            v.to_pos2()
        })
        .collect()
}

fn p(x: f32, y: f32) -> Pos2 {
    pos2(x, y)
}

fn open(points: &[(f32, f32)]) -> Part {
    Part::Open(points.iter().map(|&(x, y)| p(x, y)).collect())
}

fn closed(points: &[(f32, f32)]) -> Part {
    Part::Closed(points.iter().map(|&(x, y)| p(x, y)).collect())
}

fn shield() -> Part {
    let mut points = vec![p(10.0, 2.5), p(16.0, 4.8), p(16.0, 9.4)];
    points.extend(
        cubic(p(16.0, 9.4), p(16.0, 13.3), p(13.4, 16.0), p(10.0, 17.5), 8)
            .into_iter()
            .skip(1),
    );
    points.extend(
        cubic(p(10.0, 17.5), p(6.6, 16.0), p(4.0, 13.3), p(4.0, 9.4), 8)
            .into_iter()
            .skip(1),
    );
    points.push(p(4.0, 4.8));
    Part::Closed(points)
}

fn gear() -> Vec<Part> {
    let n = 8;
    let mut points = Vec::new();
    for i in 0..n {
        let a = i as f32 / n as f32 * TAU;
        let t = PI / n as f32;
        for (angle, r) in [
            (a - t * 0.95, 5.9),
            (a - t * 0.45, 7.6),
            (a + t * 0.45, 7.6),
            (a + t * 0.95, 5.9),
        ] {
            points.push(p(10.0, 10.0) + Vec2::angled(angle) * r);
        }
    }
    vec![Part::Closed(points), Part::Circle(p(10.0, 10.0), 2.4)]
}

pub fn parts(icon: Icon) -> Vec<Part> {
    match icon {
        Icon::Shield => vec![shield()],
        Icon::ShieldCheck => vec![shield(), open(&[(7.3, 10.0), (9.2, 11.9), (12.8, 8.1)])],
        Icon::Uac => vec![
            shield(),
            open(&[(10.0, 2.8), (10.0, 17.2)]),
            open(&[(4.2, 9.5), (15.8, 9.5)]),
        ],
        Icon::Log => vec![
            Part::RoundRect(p(4.0, 2.8), vec2(12.0, 14.4), 2.0),
            open(&[(7.0, 7.0), (13.0, 7.0)]),
            open(&[(7.0, 10.0), (13.0, 10.0)]),
            open(&[(7.0, 13.0), (10.5, 13.0)]),
        ],
        Icon::Gear => gear(),
        Icon::ChevronRight => vec![open(&[(8.0, 5.0), (13.0, 10.0), (8.0, 15.0)])],
        Icon::ChevronDown => vec![open(&[(5.0, 8.0), (10.0, 13.0), (15.0, 8.0)])],
        Icon::ChevronUp => vec![open(&[(5.0, 12.0), (10.0, 7.0), (15.0, 12.0)])],
        Icon::Back => vec![
            open(&[(16.0, 10.0), (4.5, 10.0)]),
            open(&[(9.0, 5.0), (4.0, 10.0), (9.0, 15.0)]),
        ],
        Icon::Plus => vec![
            open(&[(10.0, 4.0), (10.0, 16.0)]),
            open(&[(4.0, 10.0), (16.0, 10.0)]),
        ],
        Icon::More => vec![
            Part::Dot(p(10.0, 4.6), 1.8),
            Part::Dot(p(10.0, 10.0), 1.8),
            Part::Dot(p(10.0, 15.4), 1.8),
        ],
        Icon::Copy => vec![
            Part::RoundRect(p(7.0, 7.0), vec2(9.5, 9.5), 2.0),
            open(&[
                (13.0, 4.6),
                (12.6, 3.4),
                (11.5, 3.0),
                (5.5, 3.0),
                (4.4, 3.4),
                (4.0, 4.5),
                (4.0, 10.5),
                (4.4, 11.6),
                (5.5, 12.0),
                (5.7, 12.0),
            ]),
        ],
        Icon::Trash => vec![
            open(&[(3.5, 5.5), (16.5, 5.5)]),
            open(&[
                (8.0, 5.5),
                (8.0, 4.0),
                (9.0, 3.0),
                (11.0, 3.0),
                (12.0, 4.0),
                (12.0, 5.5),
            ]),
            open(&[
                (5.2, 5.5),
                (5.9, 15.7),
                (7.4, 17.0),
                (12.6, 17.0),
                (14.1, 15.7),
                (14.8, 5.5),
            ]),
        ],
        Icon::Up => vec![
            open(&[(10.0, 16.0), (10.0, 4.5)]),
            open(&[(5.0, 9.5), (10.0, 4.5), (15.0, 9.5)]),
        ],
        Icon::Down => vec![
            open(&[(10.0, 4.0), (10.0, 15.5)]),
            open(&[(5.0, 10.5), (10.0, 15.5), (15.0, 10.5)]),
        ],
        Icon::Close => vec![
            open(&[(5.0, 5.0), (15.0, 15.0)]),
            open(&[(15.0, 5.0), (5.0, 15.0)]),
        ],
        Icon::Check => vec![open(&[(4.5, 10.5), (8.0, 14.0), (15.5, 6.0)])],
        Icon::Refresh => vec![
            Part::Open(arc(p(10.0, 10.0), 6.0, 0.0, 314.4_f32.to_radians(), 40)),
            open(&[(16.2, 3.5), (16.2, 6.8), (12.9, 6.8)]),
        ],
        Icon::Key => vec![
            Part::Circle(p(6.8, 13.2), 3.3),
            open(&[(9.2, 10.8), (16.2, 3.8)]),
            open(&[(13.6, 6.4), (15.6, 8.4)]),
            open(&[(11.8, 8.2), (13.4, 9.8)]),
        ],
        Icon::Lock => {
            let mut shackle = vec![p(6.8, 8.5)];
            shackle.extend(arc(p(10.0, 6.2), 3.2, PI, PI, 16));
            shackle.push(p(13.2, 8.5));
            vec![
                Part::RoundRect(p(4.0, 8.5), vec2(12.0, 8.5), 2.0),
                Part::Open(shackle),
            ]
        }
        Icon::Warning => vec![
            closed(&[(10.0, 3.2), (17.6, 16.6), (2.4, 16.6)]),
            open(&[(10.0, 8.0), (10.0, 11.6)]),
            Part::Dot(p(10.0, 14.2), 1.0),
        ],
        Icon::Info => vec![
            Part::Circle(p(10.0, 10.0), 7.0),
            open(&[(10.0, 9.2), (10.0, 13.8)]),
            Part::Dot(p(10.0, 6.6), 1.0),
        ],
        Icon::Error => vec![
            Part::Circle(p(10.0, 10.0), 7.0),
            open(&[(7.5, 7.5), (12.5, 12.5)]),
            open(&[(12.5, 7.5), (7.5, 12.5)]),
        ],
        Icon::Ok => vec![
            Part::Circle(p(10.0, 10.0), 7.0),
            open(&[(7.0, 10.2), (9.1, 12.3), (13.1, 8.0)]),
        ],
        Icon::Dot => vec![Part::Dot(p(10.0, 10.0), 2.2)],
        Icon::User => vec![
            Part::Circle(p(10.0, 7.0), 3.2),
            Part::Open(arc(p(10.0, 17.0), 6.2, PI, PI, 24)),
        ],
        Icon::Rosette => vec![
            Part::Circle(p(10.0, 8.0), 5.0),
            open(&[
                (7.2, 12.2),
                (6.2, 17.5),
                (10.0, 15.5),
                (13.8, 17.5),
                (12.8, 12.2),
            ]),
            open(&[(8.0, 8.0), (9.4, 9.4), (12.2, 6.6)]),
        ],
        Icon::Download => vec![
            open(&[(10.0, 3.0), (10.0, 12.0)]),
            open(&[(6.2, 8.4), (10.0, 12.2), (13.8, 8.4)]),
            open(&[
                (3.5, 13.0),
                (3.5, 14.7),
                (4.2, 16.3),
                (5.8, 17.0),
                (14.2, 17.0),
                (15.8, 16.3),
                (16.5, 14.7),
                (16.5, 13.0),
            ]),
        ],
        Icon::ArrowDown => vec![
            open(&[(10.0, 4.0), (10.0, 16.0)]),
            open(&[(5.5, 11.5), (10.0, 16.0), (14.5, 11.5)]),
        ],
        Icon::ArrowUp => vec![
            open(&[(10.0, 16.0), (10.0, 4.0)]),
            open(&[(5.5, 8.5), (10.0, 4.0), (14.5, 8.5)]),
        ],
        Icon::Eye => {
            let mut almond = Vec::new();
            for i in 0..=32 {
                let t = i as f32 / 32.0 * TAU;
                almond.push(p(10.0 + 7.5 * t.cos(), 10.0 - 5.2 * t.sin()));
            }
            vec![Part::Closed(almond), Part::Circle(p(10.0, 10.0), 2.3)]
        }
        Icon::External => vec![
            open(&[(11.5, 3.5), (16.5, 3.5), (16.5, 8.5)]),
            open(&[(16.5, 3.5), (9.5, 10.5)]),
            open(&[
                (14.0, 11.5),
                (14.0, 14.8),
                (12.3, 16.5),
                (5.2, 16.5),
                (3.5, 14.8),
                (3.5, 7.7),
                (5.2, 6.0),
                (8.5, 6.0),
            ]),
        ],
        Icon::Paste => vec![
            Part::RoundRect(p(5.0, 4.0), vec2(10.0, 13.0), 2.0),
            open(&[
                (8.0, 4.0),
                (8.0, 3.2),
                (8.7, 2.5),
                (11.3, 2.5),
                (12.0, 3.2),
                (12.0, 4.0),
            ]),
        ],
        Icon::Edit => vec![closed(&[
            (12.8, 3.6),
            (15.4, 6.2),
            (7.0, 14.6),
            (3.6, 15.4),
            (4.4, 12.0),
        ])],
        Icon::Power => vec![
            open(&[(10.0, 2.8), (10.0, 9.2)]),
            Part::Open(arc(
                p(10.0, 9.77),
                6.2,
                224.8_f32.to_radians(),
                -269.6_f32.to_radians(),
                40,
            )),
        ],
    }
}

/// Draws `icon` in `rect` (kept square, centred) in `color`, with the constant icon stroke.
pub fn paint(painter: &Painter, rect: Rect, icon: Icon, color: Color32) {
    paint_width(painter, rect, icon, color, STROKE);
}

/// Like [`paint`] with a stroke of `width` points.
pub fn paint_width(painter: &Painter, rect: Rect, icon: Icon, color: Color32, width: f32) {
    let side = rect.width().min(rect.height());
    let scale = side / 20.0;
    let origin = rect.center() - vec2(side, side) / 2.0;
    let map = |q: Pos2| origin + q.to_vec2() * scale;
    let stroke = Stroke::new(width, color);
    for part in parts(icon) {
        match part {
            Part::Open(points) => {
                let points: Vec<Pos2> = points.into_iter().map(map).collect();
                // Round the ends and joins: egui strokes have neither.
                for q in &points {
                    painter.circle_filled(*q, width / 2.0, color);
                }
                painter.add(Shape::line(points, stroke));
            }
            Part::Closed(points) => {
                let points: Vec<Pos2> = points.into_iter().map(map).collect();
                for q in &points {
                    painter.circle_filled(*q, width / 2.0, color);
                }
                painter.add(Shape::closed_line(points, stroke));
            }
            Part::Circle(center, radius) => {
                painter.circle_stroke(map(center), radius * scale, stroke);
            }
            Part::Dot(center, radius) => {
                painter.circle_filled(map(center), (radius * scale).max(width * 0.6), color);
            }
            Part::RoundRect(min, size, radius) => {
                painter.rect_stroke(
                    Rect::from_min_size(map(min), size * scale),
                    CornerRadius::same((radius * scale).round() as u8),
                    stroke,
                    StrokeKind::Middle,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Icon; 35] = [
        Icon::Shield,
        Icon::ShieldCheck,
        Icon::Uac,
        Icon::Log,
        Icon::Gear,
        Icon::ChevronRight,
        Icon::ChevronDown,
        Icon::ChevronUp,
        Icon::Back,
        Icon::Plus,
        Icon::More,
        Icon::Copy,
        Icon::Trash,
        Icon::Up,
        Icon::Down,
        Icon::Close,
        Icon::Check,
        Icon::Refresh,
        Icon::Key,
        Icon::Lock,
        Icon::Warning,
        Icon::Info,
        Icon::Error,
        Icon::Ok,
        Icon::Dot,
        Icon::User,
        Icon::Rosette,
        Icon::Download,
        Icon::ArrowDown,
        Icon::ArrowUp,
        Icon::Eye,
        Icon::External,
        Icon::Paste,
        Icon::Edit,
        Icon::Power,
    ];

    #[test]
    fn every_icon_stays_on_its_grid() {
        let inside = |q: Pos2| (0.0..=20.0).contains(&q.x) && (0.0..=20.0).contains(&q.y);
        for icon in ALL {
            let parts = parts(icon);
            assert!(!parts.is_empty(), "{icon:?}");
            for part in parts {
                match part {
                    Part::Open(points) | Part::Closed(points) => {
                        assert!(points.len() >= 2, "{icon:?}");
                        assert!(points.into_iter().all(inside), "{icon:?}");
                    }
                    Part::Circle(c, r) | Part::Dot(c, r) => {
                        assert!(inside(c) && c.x - r >= 0.0 && c.x + r <= 20.0, "{icon:?}");
                        assert!(c.y - r >= 0.0 && c.y + r <= 20.0, "{icon:?}");
                    }
                    Part::RoundRect(min, size, _) => {
                        assert!(inside(min) && inside(min + size), "{icon:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn arcs_have_their_ends_where_asked() {
        let points = arc(pos2(0.0, 0.0), 10.0, 0.0, PI, 10);
        assert_eq!(points.len(), 11);
        assert!((points[0] - pos2(10.0, 0.0)).length() < 1e-4);
        assert!((points[10] - pos2(-10.0, 0.0)).length() < 1e-4);
    }

    #[test]
    fn the_power_ring_opens_at_the_top() {
        let Part::Open(ring) = &parts(Icon::Power)[1] else {
            panic!("the ring is an open line");
        };
        let (first, last) = (ring[0], ring[ring.len() - 1]);
        assert!((first - pos2(5.6, 5.4)).length() < 0.1, "{first:?}");
        assert!((last - pos2(14.4, 5.4)).length() < 0.1, "{last:?}");
    }
}
