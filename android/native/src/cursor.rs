//! The pointer the app draws over the remote screen (the host sends only the cursor's shape):
//! a few classic shapes, white with a black outline so they show on any background.

use crate::proto::Cursor;

/// An RGBA sprite and its hot spot.
pub struct Sprite {
    pub w: usize,
    pub h: usize,
    pub hot: (usize, usize),
    pub rgba: Vec<u8>,
}

/// 'B' black, 'W' white, anything else transparent.
const ARROW: &[&str] = &[
    "B",
    "BB",
    "BWB",
    "BWWB",
    "BWWWB",
    "BWWWWB",
    "BWWWWWB",
    "BWWWWWWB",
    "BWWWWWWWB",
    "BWWWWWWWWB",
    "BWWWWWWWWWB",
    "BWWWWWWBBBBB",
    "BWWWBWWB",
    "BWWB BWWB",
    "BWB  BWWB",
    "BB    BWWB",
    "B     BWWB",
    "       BWWB",
    "       BBB",
];

const IBEAM: &[&str] = &[
    "BBBB BBBB",
    "BWWWBWWWB",
    "BBBBWBBBB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "   BWB",
    "BBBBWBBBB",
    "BWWWBWWWB",
    "BBBB BBBB",
];

const CROSS: &[&str] = &[
    "    BBB",
    "    BWB",
    "    BWB",
    "    BWB",
    "BBBBBWBBBBB",
    "BWWWWWWWWWB",
    "BBBBBWBBBBB",
    "    BWB",
    "    BWB",
    "    BWB",
    "    BBB",
];

fn sprite(art: &[&str], hot: (usize, usize)) -> Sprite {
    let w = art.iter().map(|r| r.len()).max().unwrap_or(0);
    let h = art.len();
    let mut rgba = vec![0u8; w * h * 4];
    for (y, row) in art.iter().enumerate() {
        for (x, c) in row.bytes().enumerate() {
            let px = match c {
                b'B' => [0, 0, 0, 255],
                b'W' => [255, 255, 255, 255],
                _ => continue,
            };
            rgba[(y * w + x) * 4..][..4].copy_from_slice(&px);
        }
    }
    Sprite { w, h, hot, rgba }
}

/// The sprite for `c` (`None`: draw nothing).
pub fn sprite_for(c: Cursor) -> Option<Sprite> {
    match c {
        Cursor::Hidden => None,
        Cursor::IBeam => Some(sprite(IBEAM, (4, 8))),
        Cursor::Cross => Some(sprite(CROSS, (5, 5))),
        _ => Some(sprite(ARROW, (0, 0))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sprites_are_well_formed() {
        for c in Cursor::ALL {
            let Some(s) = sprite_for(c) else { continue };
            assert_eq!(s.rgba.len(), s.w * s.h * 4);
            assert!(s.hot.0 < s.w && s.hot.1 < s.h);
            // The hot spot is drawn (the pointer's tip is visible).
            assert_eq!(s.rgba[(s.hot.1 * s.w + s.hot.0) * 4 + 3], 255, "{c:?}");
        }
        assert!(sprite_for(Cursor::Hidden).is_none());
    }
}
