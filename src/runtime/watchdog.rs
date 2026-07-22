pub struct Watchdog;

impl Watchdog {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}
