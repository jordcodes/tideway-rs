//! Log capture for unit tests that run in parallel in one process.
//!
//! `tracing` caches each callsite's `Interest` the first time it fires. A scoped subscriber
//! (`with_default`/`set_default`) is invisible to other threads, so if another test first fires a
//! callsite while only one dispatcher is registered, that thread computes `Interest::never` from
//! its own (empty) default and caches it. The capturing test then silently misses the event.
//!
//! Instead, a single global subscriber is installed once. It is visible from every thread, so a
//! callsite's cached interest can never exclude it, and it writes only on threads that currently
//! hold a [`LogCapture`].

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, filter};

type Buffer = Arc<Mutex<Vec<u8>>>;

thread_local! {
    static ACTIVE: RefCell<Option<Buffer>> = const { RefCell::new(None) };
}

fn is_capturing() -> bool {
    ACTIVE.with(|active| active.borrow().is_some())
}

struct ThreadWriter;

impl io::Write for ThreadWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        ACTIVE.with(|active| {
            if let Some(buffer) = active.borrow().as_ref() {
                buffer.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for ThreadWriter {
    type Writer = ThreadWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ThreadWriter
    }
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .without_time()
            .with_ansi(false)
            .with_writer(ThreadWriter)
            // Dynamic, so callsites cache `sometimes` and the check runs per event.
            .with_filter(filter::dynamic_filter_fn(|_, _| is_capturing()));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
            .expect("unit tests must not install another global tracing subscriber");
    });
}

/// Captures every event emitted on the current thread at any level until dropped.
///
/// Must not be combined with a scoped subscriber on the same thread, which would shadow the
/// global one.
pub(crate) struct LogCapture {
    buffer: Buffer,
}

impl LogCapture {
    pub(crate) fn start() -> Self {
        install();
        let buffer = Buffer::default();
        ACTIVE.with(|active| {
            let previous = active.borrow_mut().replace(buffer.clone());
            assert!(previous.is_none(), "log captures cannot be nested");
        });
        Self { buffer }
    }

    pub(crate) fn output(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.borrow_mut().take());
    }
}
