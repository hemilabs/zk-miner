//! The process environment, as this crate reads it to size and admit work on a card.
//!
//! Outside tests this is `std::env::var(name).ok()`. A unit test can replace the whole environment
//! for its own thread (`Hermetic`), so a variable set in the shell that runs the tests
//! (`SP1_GPU_ELEMENT_THRESHOLD`, `ZKMINER_MIN_AVAILABLE_VRAM_MB`, ...) cannot change what it checks.

/// `name`'s value, `None` when unset (or not Unicode), as `std::env::var(name).ok()`, unless a test
/// on this thread has replaced the environment.
pub(crate) fn var(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(value) = HERMETIC.with(|h| h.borrow().as_ref().map(|vars| vars.get(name).cloned()))
    {
        return value;
    }
    std::env::var(name).ok()
}

#[cfg(test)]
thread_local! {
    static HERMETIC: std::cell::RefCell<Option<std::collections::HashMap<String, String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: while alive, this thread's `var` sees `vars` and nothing else.
#[cfg(test)]
pub(crate) struct Hermetic {
    previous: Option<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
impl Hermetic {
    pub(crate) fn new(vars: &[(&str, &str)]) -> Self {
        let vars = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            previous: HERMETIC.with(|h| h.borrow_mut().replace(vars)),
        }
    }
}

#[cfg(test)]
impl Drop for Hermetic {
    fn drop(&mut self) {
        let previous = self.previous.take();
        HERMETIC.with(|h| *h.borrow_mut() = previous);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_hermetic_environment_is_the_whole_environment_for_its_thread() {
        // PATH is set in any shell that runs these tests.
        assert!(super::var("PATH").is_some());
        {
            let _env = super::Hermetic::new(&[("ZKMINER_TEST_ONLY", "1")]);
            assert_eq!(super::var("PATH"), None);
            assert_eq!(super::var("ZKMINER_TEST_ONLY").as_deref(), Some("1"));
            {
                let _inner = super::Hermetic::new(&[]);
                assert_eq!(super::var("ZKMINER_TEST_ONLY"), None);
            }
            assert_eq!(super::var("ZKMINER_TEST_ONLY").as_deref(), Some("1"));
            // Another thread still sees the process's.
            assert!(std::thread::spawn(|| super::var("PATH"))
                .join()
                .unwrap()
                .is_some());
        }
        assert!(super::var("PATH").is_some());
    }
}
