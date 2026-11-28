//! Line icons drawn with the painter (the bundled fonts have no icon glyphs). Each icon is
//! designed on a 24 × 24 grid and scaled to the rectangle it is drawn in.

use std::f32::consts::{PI, TAU};

use eframe::egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, Vec2, pos2, vec2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    Power,
    Shield,
    ShieldCheck,
    List,
    Activity,
    Gear,
    ChevronDown,
    Back,
    Up,
    Down,
    Plus,
    Close,
    Copy,
    Trash,
    Warning,
}

/// One stroke of an icon, on the 24 × 24 grid.
#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Open(Vec<Pos2>),
    Closed(Vec<Pos2>),
    Circle(Pos2, f32),
    /// A filled dot.
    Dot(Pos2, f32),
}

/// Points along a circle from angle `from` (radians, 0 = right, clockwise on screen) through
/// `sweep`.
pub fn arc(center: Pos2, radius: f32, from: f32, sweep: f32, steps: usize) -> Vec<Pos2> {
    (0..=steps)
        .map(|i| center + radius * Vec2::angled(from + sweep * i as f32 / steps as f32))
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

pub fn parts(icon: Icon) -> Vec<Part> {
    match icon {
        Icon::Power => vec![
            open(&[(12.0, 3.0), (12.0, 11.0)]),
            // An open ring with the gap at the top.
            Part::Open(arc(p(12.0, 13.0), 8.0, -PI / 2.0 + 0.75, TAU - 1.5, 32)),
        ],
        Icon::Shield | Icon::ShieldCheck => {
            let mut v = vec![closed(&[
                (12.0, 3.0),
                (20.0, 6.0),
                (20.0, 12.0),
                (18.5, 16.0),
                (12.0, 21.0),
                (5.5, 16.0),
                (4.0, 12.0),
                (4.0, 6.0),
            ])];
            if icon == Icon::ShieldCheck {
                v.push(open(&[(9.0, 12.0), (11.0, 14.0), (15.0, 10.0)]));
            }
            v
        }
        Icon::List => vec![
            open(&[(4.0, 6.0), (20.0, 6.0)]),
            open(&[(4.0, 12.0), (20.0, 12.0)]),
            open(&[(4.0, 18.0), (20.0, 18.0)]),
        ],
        Icon::Activity => vec![open(&[
            (3.0, 12.0),
            (7.0, 12.0),
            (10.0, 20.0),
            (14.0, 4.0),
            (17.0, 12.0),
            (21.0, 12.0),
        ])],
        Icon::Gear => {
            let mut v = vec![Part::Circle(p(12.0, 12.0), 3.0)];
            for i in 0..8 {
                let a = i as f32 * TAU / 8.0;
                let d = Vec2::angled(a);
                v.push(Part::Open(vec![
                    p(12.0, 12.0) + d * 6.0,
                    p(12.0, 12.0) + d * 9.0,
                ]));
            }
            v.push(Part::Circle(p(12.0, 12.0), 6.0));
            v
        }
        Icon::ChevronDown | Icon::Down => vec![open(&[(6.0, 9.0), (12.0, 15.0), (18.0, 9.0)])],
        Icon::Back => vec![open(&[(15.0, 6.0), (9.0, 12.0), (15.0, 18.0)])],
        Icon::Up => vec![open(&[(6.0, 15.0), (12.0, 9.0), (18.0, 15.0)])],
        Icon::Plus => vec![
            open(&[(12.0, 5.0), (12.0, 19.0)]),
            open(&[(5.0, 12.0), (19.0, 12.0)]),
        ],
        Icon::Close => vec![
            open(&[(6.0, 6.0), (18.0, 18.0)]),
            open(&[(18.0, 6.0), (6.0, 18.0)]),
        ],
        Icon::Copy => vec![
            closed(&[(8.0, 8.0), (20.0, 8.0), (20.0, 20.0), (8.0, 20.0)]),
            open(&[
                (16.0, 8.0),
                (16.0, 4.0),
                (4.0, 4.0),
                (4.0, 16.0),
                (8.0, 16.0),
            ]),
        ],
        Icon::Trash => vec![
            open(&[(4.0, 7.0), (20.0, 7.0)]),
            open(&[(9.0, 7.0), (9.0, 4.0), (15.0, 4.0), (15.0, 7.0)]),
            open(&[(6.0, 7.0), (7.0, 20.0), (17.0, 20.0), (18.0, 7.0)]),
        ],
        Icon::Warning => vec![
            closed(&[(12.0, 3.0), (22.0, 20.0), (2.0, 20.0)]),
            open(&[(12.0, 9.0), (12.0, 14.0)]),
            Part::Dot(p(12.0, 17.0), 1.1),
        ],
    }
}

/// Draws `icon` in `rect` (kept square, centred) with lines of `width` (at 24 points).
pub fn paint(painter: &Painter, rect: Rect, icon: Icon, color: Color32, width: f32) {
    let side = rect.width().min(rect.height());
    let scale = side / 24.0;
    let origin = rect.center() - vec2(side, side) / 2.0;
    let map = |q: Pos2| origin + q.to_vec2() * scale;
    let stroke = Stroke::new(width * scale.max(0.6), color);
    for part in parts(icon) {
        match part {
            Part::Open(points) => {
                let points: Vec<Pos2> = points.into_iter().map(map).collect();
                // Round the ends: egui joins lines without caps.
                for end in [points.first(), points.last()].into_iter().flatten() {
                    painter.circle_filled(*end, stroke.width / 2.0, color);
                }
                painter.add(Shape::line(points, stroke));
            }
            Part::Closed(points) => {
                painter.add(Shape::closed_line(
                    points.into_iter().map(map).collect(),
                    stroke,
                ));
            }
            Part::Circle(center, radius) => {
                painter.circle_stroke(map(center), radius * scale, stroke);
            }
            Part::Dot(center, radius) => {
                painter.circle_filled(map(center), radius * scale, color);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_stays_on_its_grid() {
        let all = [
            Icon::Power,
            Icon::Shield,
            Icon::ShieldCheck,
            Icon::List,
            Icon::Activity,
            Icon::Gear,
            Icon::ChevronDown,
            Icon::Back,
            Icon::Up,
            Icon::Down,
            Icon::Plus,
            Icon::Close,
            Icon::Copy,
            Icon::Trash,
            Icon::Warning,
        ];
        let inside = |q: Pos2| (0.0..=24.0).contains(&q.x) && (0.0..=24.0).contains(&q.y);
        for icon in all {
            let parts = parts(icon);
            assert!(!parts.is_empty(), "{icon:?}");
            for part in parts {
                match part {
                    Part::Open(points) | Part::Closed(points) => {
                        assert!(points.len() >= 2, "{icon:?}");
                        assert!(points.into_iter().all(inside), "{icon:?}");
                    }
                    Part::Circle(c, r) | Part::Dot(c, r) => {
                        assert!(inside(c) && c.x - r >= 0.0 && c.x + r <= 24.0, "{icon:?}");
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
}
