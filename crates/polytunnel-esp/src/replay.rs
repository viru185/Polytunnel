//! Anti-replay window (RFC 4303 §3.4.3, sliding bitmap as in RFC 4303 appendix A).

/// Remembers which recent sequence numbers were seen. `check` before verifying a packet,
/// `update` only after it authenticated, so forged packets cannot move the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    size: u32,
    /// Highest sequence number accepted so far (0: none yet).
    top: u32,
    /// Bit `i` set: `top - i` was seen.
    bits: Vec<u64>,
}

impl ReplayWindow {
    /// `size` packets, clamped to 64..=1024 and rounded up to a multiple of 64.
    pub fn new(size: usize) -> Self {
        let words = size.clamp(64, 1024).div_ceil(64);
        ReplayWindow {
            size: (words * 64) as u32,
            top: 0,
            bits: vec![0; words],
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Would `seq` be accepted?
    pub fn check(&self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.top {
            return true;
        }
        let offset = self.top - seq;
        offset < self.size && !self.bit(offset)
    }

    /// Records `seq` as seen (call only for authenticated packets that passed `check`).
    pub fn update(&mut self, seq: u32) {
        if seq > self.top {
            self.shift(seq - self.top);
            self.top = seq;
            self.set(0);
        } else if self.top - seq < self.size {
            self.set(self.top - seq);
        }
    }

    fn bit(&self, offset: u32) -> bool {
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        self.bits[word] & (1 << bit) != 0
    }

    fn set(&mut self, offset: u32) {
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        self.bits[word] |= 1 << bit;
    }

    /// Moves every remembered offset up by `n` (older), dropping what falls out.
    fn shift(&mut self, n: u32) {
        if n >= self.size {
            self.bits.iter_mut().for_each(|w| *w = 0);
            return;
        }
        let words = (n / 64) as usize;
        let bits = n % 64;
        let len = self.bits.len();
        for i in (0..len).rev() {
            let src = i.checked_sub(words);
            let lo = src.map_or(0, |s| self.bits[s]);
            let carry = match (bits, src.and_then(|s| s.checked_sub(1))) {
                (0, _) | (_, None) => 0,
                (b, Some(s)) => self.bits[s] >> (64 - b),
            };
            self.bits[i] = if bits == 0 { lo } else { (lo << bits) | carry };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(w: &mut ReplayWindow, seq: u32) -> bool {
        let ok = w.check(seq);
        if ok {
            w.update(seq);
        }
        ok
    }

    #[test]
    fn in_order_out_of_order_and_duplicates() {
        let mut w = ReplayWindow::new(64);
        assert!(!accept(&mut w, 0));
        assert!(accept(&mut w, 1));
        assert!(accept(&mut w, 3));
        assert!(accept(&mut w, 2)); // late but inside the window
        assert!(!accept(&mut w, 2)); // duplicate
        assert!(!accept(&mut w, 3));
        assert!(accept(&mut w, 100));
        assert!(!accept(&mut w, 36)); // 100 - 36 = 64: just outside
        assert!(accept(&mut w, 37)); // offset 63: inside
        assert!(!accept(&mut w, 37));
    }

    #[test]
    fn large_windows_shift_across_words() {
        let mut w = ReplayWindow::new(1000);
        assert_eq!(w.size(), 1024);
        for seq in 1..=300 {
            assert!(accept(&mut w, seq));
        }
        assert!(accept(&mut w, 1000));
        // 1..=300 are still inside the window (1000 - 300 < 1024) and must stay seen.
        for seq in [1, 63, 64, 65, 128, 129, 300] {
            assert!(!w.check(seq), "{seq} should be remembered");
        }
        assert!(w.check(500));
        assert!(accept(&mut w, 1000 + 1024)); // jump past everything
        assert!(!w.check(1000)); // now too old
        assert!(w.check(1000 + 1023));
    }

    #[test]
    fn unauthenticated_checks_do_not_move_the_window() {
        let mut w = ReplayWindow::new(64);
        assert!(accept(&mut w, 10));
        assert!(w.check(5000)); // checked but never updated (e.g. failed integrity)
        assert!(w.check(9));
    }
}
