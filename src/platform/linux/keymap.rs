//! Key translation between the wire format (Windows set-1 scancode + extended flag, plus a
//! virtual-key code) and Linux evdev keycodes. On evdev/xkb X servers (Xorg, Xvfb, Xwayland)
//! the X keycode is the evdev code + 8.
//!
//! Keys are matched by position (scancode), so the host's keyboard layout decides which
//! character a key produces, exactly as on a local keyboard. A few keys only make sense by
//! virtual-key code: Pause (its scancode collides with Num Lock), and the Korean Hangul and
//! Hanja keys, which Korean layouts also put on Right Alt / Right Ctrl.

pub const VK_SHIFT: u16 = 0x10;
pub const VK_CONTROL: u16 = 0x11;
pub const VK_MENU: u16 = 0x12;
pub const VK_PAUSE: u16 = 0x13;
pub const VK_HANGUL: u16 = 0x15;
pub const VK_HANJA: u16 = 0x19;
/// Windows' virtual key for a character typed as Unicode; its "scancode" is the character.
const VK_PACKET: u16 = 0xe7;

pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_END: u16 = 107;
pub const KEY_PAUSE: u16 = 119;
pub const KEY_HANGEUL: u16 = 122;
pub const KEY_HANJA: u16 = 123;

/// Offset between evdev codes and X keycodes on evdev/xkb servers.
pub const X_KEYCODE_OFFSET: u16 = 8;

/// One row per physical key: (evdev code, set-1 scancode, extended, US-layout virtual key).
/// A virtual key of 0 means "layout-specific, send the scancode only". Power, Sleep and Wake
/// are deliberately absent: a viewer must not be able to switch the host off.
const KEYS: &[(u16, u16, bool, u16)] = &[
    (1, 0x01, false, 0x1b), // Esc
    (2, 0x02, false, 0x31),
    (3, 0x03, false, 0x32),
    (4, 0x04, false, 0x33),
    (5, 0x05, false, 0x34),
    (6, 0x06, false, 0x35),
    (7, 0x07, false, 0x36),
    (8, 0x08, false, 0x37),
    (9, 0x09, false, 0x38),
    (10, 0x0a, false, 0x39),
    (11, 0x0b, false, 0x30),
    (12, 0x0c, false, 0xbd), // -
    (13, 0x0d, false, 0xbb), // =
    (14, 0x0e, false, 0x08), // Backspace
    (15, 0x0f, false, 0x09), // Tab
    (16, 0x10, false, 0x51), // Q
    (17, 0x11, false, 0x57),
    (18, 0x12, false, 0x45),
    (19, 0x13, false, 0x52),
    (20, 0x14, false, 0x54),
    (21, 0x15, false, 0x59),
    (22, 0x16, false, 0x55),
    (23, 0x17, false, 0x49),
    (24, 0x18, false, 0x4f),
    (25, 0x19, false, 0x50), // P
    (26, 0x1a, false, 0xdb), // [
    (27, 0x1b, false, 0xdd), // ]
    (28, 0x1c, false, 0x0d), // Enter
    (29, 0x1d, false, 0xa2), // Left Ctrl
    (30, 0x1e, false, 0x41), // A
    (31, 0x1f, false, 0x53),
    (32, 0x20, false, 0x44),
    (33, 0x21, false, 0x46),
    (34, 0x22, false, 0x47),
    (35, 0x23, false, 0x48),
    (36, 0x24, false, 0x4a),
    (37, 0x25, false, 0x4b),
    (38, 0x26, false, 0x4c), // L
    (39, 0x27, false, 0xba), // ;
    (40, 0x28, false, 0xde), // '
    (41, 0x29, false, 0xc0), // `
    (42, 0x2a, false, 0xa0), // Left Shift
    (43, 0x2b, false, 0xdc), // backslash
    (44, 0x2c, false, 0x5a), // Z
    (45, 0x2d, false, 0x58),
    (46, 0x2e, false, 0x43),
    (47, 0x2f, false, 0x56),
    (48, 0x30, false, 0x42),
    (49, 0x31, false, 0x4e),
    (50, 0x32, false, 0x4d), // M
    (51, 0x33, false, 0xbc), // ,
    (52, 0x34, false, 0xbe), // .
    (53, 0x35, false, 0xbf), // /
    (54, 0x36, false, 0xa1), // Right Shift
    (55, 0x37, false, 0x6a), // Keypad *
    (56, 0x38, false, 0xa4), // Left Alt
    (57, 0x39, false, 0x20), // Space
    (58, 0x3a, false, 0x14), // Caps Lock
    (59, 0x3b, false, 0x70), // F1
    (60, 0x3c, false, 0x71),
    (61, 0x3d, false, 0x72),
    (62, 0x3e, false, 0x73),
    (63, 0x3f, false, 0x74),
    (64, 0x40, false, 0x75),
    (65, 0x41, false, 0x76),
    (66, 0x42, false, 0x77),
    (67, 0x43, false, 0x78),
    (68, 0x44, false, 0x79), // F10
    (69, 0x45, true, 0x90),  // Num Lock (Windows reports it extended)
    (70, 0x46, false, 0x91), // Scroll Lock
    (71, 0x47, false, 0x67), // Keypad 7
    (72, 0x48, false, 0x68),
    (73, 0x49, false, 0x69),
    (74, 0x4a, false, 0x6d), // Keypad -
    (75, 0x4b, false, 0x64),
    (76, 0x4c, false, 0x65),
    (77, 0x4d, false, 0x66),
    (78, 0x4e, false, 0x6b), // Keypad +
    (79, 0x4f, false, 0x61),
    (80, 0x50, false, 0x62),
    (81, 0x51, false, 0x63),
    (82, 0x52, false, 0x60), // Keypad 0
    (83, 0x53, false, 0x6e), // Keypad .
    (86, 0x56, false, 0xe2), // 102nd key (<>)
    (87, 0x57, false, 0x7a), // F11
    (88, 0x58, false, 0x7b), // F12
    (89, 0x73, false, 0),    // Ro (JIS / ABNT)
    (92, 0x79, false, 0x1c), // Henkan (convert)
    (93, 0x70, false, 0),    // Katakana/Hiragana
    (94, 0x7b, false, 0x1d), // Muhenkan (non-convert)
    (96, 0x1c, true, 0x0d),  // Keypad Enter
    (97, 0x1d, true, 0xa3),  // Right Ctrl
    (98, 0x35, true, 0x6f),  // Keypad /
    (99, 0x37, true, 0x2c),  // Print Screen
    (100, 0x38, true, 0xa5), // Right Alt
    (102, 0x47, true, 0x24), // Home
    (103, 0x48, true, 0x26), // Up
    (104, 0x49, true, 0x21), // Page Up
    (105, 0x4b, true, 0x25), // Left
    (106, 0x4d, true, 0x27), // Right
    (107, 0x4f, true, 0x23), // End
    (108, 0x50, true, 0x28), // Down
    (109, 0x51, true, 0x22), // Page Down
    (110, 0x52, true, 0x2d), // Insert
    (111, 0x53, true, 0x2e), // Delete
    (113, 0x20, true, 0xad), // Mute
    (114, 0x2e, true, 0xae), // Volume down
    (115, 0x30, true, 0xaf), // Volume up
    (117, 0x59, false, 0),   // Keypad =
    (119, 0, false, VK_PAUSE), // no scancode of its own: 0x45 is Num Lock
    (121, 0x7e, false, 0), // Keypad , (ABNT)
    (122, 0x72, false, VK_HANGUL),
    (123, 0x71, false, VK_HANJA),
    (124, 0x7d, false, 0),   // Yen
    (125, 0x5b, true, 0x5b), // Left Windows / Super
    (126, 0x5c, true, 0x5c), // Right Windows / Super
    (127, 0x5d, true, 0x5d), // Menu
    (128, 0x68, true, 0xa9), // Browser stop
    (140, 0x21, true, 0xb7), // Calculator
    (155, 0x6c, true, 0xb4), // Mail
    (156, 0x66, true, 0xab), // Browser favourites
    (157, 0x6b, true, 0xb6), // My computer
    (158, 0x6a, true, 0xa6), // Browser back
    (159, 0x69, true, 0xa7), // Browser forward
    (163, 0x19, true, 0xb0), // Next track
    (164, 0x22, true, 0xb3), // Play/pause
    (165, 0x10, true, 0xb1), // Previous track
    (166, 0x24, true, 0xb2), // Stop
    (172, 0x32, true, 0xac), // Browser home
    (173, 0x67, true, 0xa8), // Browser refresh
    (183, 0x64, false, 0x7c), // F13
    (184, 0x65, false, 0x7d),
    (185, 0x66, false, 0x7e),
    (186, 0x67, false, 0x7f),
    (187, 0x68, false, 0x80),
    (188, 0x69, false, 0x81),
    (189, 0x6a, false, 0x82),
    (190, 0x6b, false, 0x83),
    (191, 0x6c, false, 0x84),
    (192, 0x6d, false, 0x85),
    (193, 0x6e, false, 0x86), // F23
    (194, 0x76, false, 0x87), // F24
    (217, 0x65, true, 0xaa),  // Browser search
    (226, 0x6d, true, 0xb5),  // Media select
];

/// Scancodes Windows reports for a key that the table lists under another code.
const ALIASES: &[(u16, bool, u16)] = &[
    (0x54, false, 99),  // Alt+Print Screen (SysRq)
    (0x45, false, 69),  // Num Lock without the extended flag
    (0x46, true, 119),  // Ctrl+Pause (Break)
    (0x36, true, 54),   // Right Shift reported as extended
];

/// Generic modifier virtual keys, for senders that do not tell left from right.
const VK_ALIASES: &[(u16, u16)] = &[(VK_SHIFT, KEY_LEFTSHIFT), (VK_CONTROL, KEY_LEFTCTRL), (VK_MENU, KEY_LEFTALT)];

/// Keys sent and injected by virtual-key code alone.
pub fn is_vk_only(evdev: u16) -> bool {
    matches!(evdev, KEY_PAUSE | KEY_HANGEUL | KEY_HANJA)
}

fn scan_to_evdev(scan: u16, extended: bool) -> Option<u16> {
    KEYS.iter()
        .find(|k| k.1 == scan && k.2 == extended)
        .map(|k| k.0)
        .or_else(|| ALIASES.iter().find(|a| a.0 == scan && a.1 == extended).map(|a| a.2))
}

fn vk_to_evdev(vk: u16) -> Option<u16> {
    if vk == 0 {
        return None;
    }
    KEYS.iter().find(|k| k.3 == vk).map(|k| k.0).or_else(|| VK_ALIASES.iter().find(|a| a.0 == vk).map(|a| a.1))
}

/// The evdev keycode for a key event from the wire, or `None` if it has no Linux equivalent.
pub fn to_evdev(vk: u16, scan: u16, extended: bool) -> Option<u16> {
    // Some senders fold the E0 prefix into the scancode.
    let (scan, extended) = if scan >> 8 == 0xe0 { (scan & 0xff, true) } else { (scan, extended) };
    // Anything else beyond one byte is not a key position: a key Windows made up (AltGr's
    // Left Ctrl, 0x21D) or a character typed as Unicode. Neither may fall back to the virtual
    // key and press a real key.
    if scan > 0xff || vk == VK_PACKET {
        return None;
    }
    match vk {
        VK_PAUSE => return Some(KEY_PAUSE),
        // Dedicated Hangul/Hanja keys, or Korean layouts' Right Alt / Right Ctrl. The same
        // virtual keys mean Kana/Kanji on Japanese layouts; those go by scancode below.
        VK_HANGUL if scan == 0 || matches!((scan, extended), (0x72, _) | (0x38, true)) => return Some(KEY_HANGEUL),
        VK_HANJA if scan == 0 || matches!((scan, extended), (0x71, _) | (0x1d, true)) => return Some(KEY_HANJA),
        _ => {}
    }
    if scan != 0 && scan <= 0xff {
        if let Some(k) = scan_to_evdev(scan, extended) {
            return Some(k);
        }
    }
    vk_to_evdev(vk)
}

/// The wire representation `(vk, scan, extended)` of an evdev keycode. Virtual-key-only keys
/// carry no scancode.
pub fn from_evdev(evdev: u16) -> Option<(u16, u16, bool)> {
    let &(_, scan, ext, vk) = KEYS.iter().find(|k| k.0 == evdev)?;
    if is_vk_only(evdev) {
        return Some((vk, 0, false));
    }
    Some((vk, scan, ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn table_is_consistent() {
        let mut codes = HashSet::new();
        let mut scans = HashSet::new();
        for &(code, scan, ext, _) in KEYS {
            assert!(codes.insert(code), "evdev {code} listed twice");
            assert!(scans.insert((scan, ext)), "scancode {scan:#x}/{ext} listed twice");
            assert!(code + X_KEYCODE_OFFSET <= 255, "evdev {code} has no X keycode");
        }
        for &(scan, ext, code) in ALIASES {
            assert!(codes.contains(&code));
            assert!(!scans.contains(&(scan, ext)) || scan_to_evdev(scan, ext) == Some(code));
        }
        for bad in [(0x5e, true), (0x5f, true), (0x63, true)] {
            assert_eq!(scan_to_evdev(bad.0, bad.1), None, "power keys must not map");
        }
    }

    #[test]
    fn round_trips() {
        for &(code, scan, ext, vk) in KEYS {
            let (wvk, wscan, wext) = from_evdev(code).unwrap();
            assert_eq!(to_evdev(wvk, wscan, wext), Some(code), "evdev {code}");
            if is_vk_only(code) {
                assert_eq!((wvk, wscan, wext), (vk, 0, false));
            } else {
                assert_eq!((wvk, wscan, wext), (vk, scan, ext));
                // A sender that gives only the scancode, or only the virtual key, still lands.
                assert_eq!(to_evdev(0, scan, ext), Some(code));
            }
        }
        assert_eq!(from_evdev(0), None);
        assert_eq!(from_evdev(116), None, "KEY_POWER");
    }

    #[test]
    fn special_keys() {
        // Korean: dedicated keys, and Right Alt / Right Ctrl when the layout makes them Hangul/Hanja.
        assert_eq!(to_evdev(VK_HANGUL, 0x72, false), Some(KEY_HANGEUL));
        assert_eq!(to_evdev(VK_HANGUL, 0x72, true), Some(KEY_HANGEUL));
        assert_eq!(to_evdev(VK_HANGUL, 0x38, true), Some(KEY_HANGEUL));
        assert_eq!(to_evdev(VK_HANJA, 0x1d, true), Some(KEY_HANJA));
        assert_eq!(to_evdev(VK_HANJA, 0, false), Some(KEY_HANJA));
        assert_eq!(to_evdev(0xa5, 0x38, true), Some(KEY_RIGHTALT));
        // Japanese: VK_KANA / VK_KANJI share the codes but go by position.
        assert_eq!(to_evdev(VK_HANGUL, 0x70, false), Some(93));
        assert_eq!(to_evdev(VK_HANJA, 0x29, false), Some(41));
        // Pause vs Num Lock share scancode 0x45.
        assert_eq!(to_evdev(VK_PAUSE, 0x45, false), Some(KEY_PAUSE));
        assert_eq!(to_evdev(0x90, 0x45, true), Some(69));
        assert_eq!(to_evdev(0x90, 0x45, false), Some(69));
        assert_eq!(from_evdev(KEY_PAUSE), Some((VK_PAUSE, 0, false)));
        // E0 folded into the scancode, generic modifiers, and virtual key only.
        assert_eq!(to_evdev(0, 0xe048, false), Some(103));
        assert_eq!(to_evdev(VK_CONTROL, 0, false), Some(KEY_LEFTCTRL));
        assert_eq!(to_evdev(0x41, 0, false), Some(30));
        assert_eq!(to_evdev(0x24, 0, false), Some(102));
        // Unknown.
        assert_eq!(to_evdev(0, 0x5e, true), None);
        assert_eq!(to_evdev(0, 0x1234, false), None);
        assert_eq!(to_evdev(0xff, 0, false), None);
        // Not key positions, so not the virtual key either: AltGr's simulated Left Ctrl, and
        // characters typed as Unicode ('S', '1', U+D55C, U+E01D), which would otherwise press
        // Keypad ., N or Right Ctrl.
        assert_eq!(to_evdev(0xa2, 0x21d, false), None);
        assert_eq!(to_evdev(0xa2, 0x1d, false), Some(KEY_LEFTCTRL));
        for scan in [0x53, 0x31, 0xd55c, 0xe01d] {
            assert_eq!(to_evdev(VK_PACKET, scan, false), None, "{scan:#x}");
        }
        // The Windows viewer's mask key (vk E8) has no key here.
        assert_eq!(to_evdev(0xe8, 0, false), None);
    }
}
