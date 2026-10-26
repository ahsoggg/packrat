//! Ordered parallel pipeline: jobs run on a worker pool, results come back strictly in submission order,
//! and at most `window` results are alive at once, so memory stays bounded for huge inputs.

use crate::error::{Error, Result};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, sync_channel};

/// Number of worker threads: `0` means "all logical cores".
pub fn resolve_threads(requested: usize) -> usize {
    if requested > 0 {
        requested
    } else {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    }
}

/// Physical memory that is free right now, in bytes (4 GiB when the system does not say).
pub fn available_memory() -> u64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        // SAFETY: `status` is a plain C struct that the call fills in; its length field is set as required.
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut status) } != 0 {
            return status.ullAvailPhys;
        }
    }
    4 << 30
}

enum Slot<T> {
    Ready(T),
    Pending(Receiver<T>),
}

pub struct OrderedPool<T: Send + 'static> {
    pool: Option<ThreadPool>,
    queue: VecDeque<Slot<T>>,
    window: usize,
}

impl<T: Send + 'static> OrderedPool<T> {
    pub fn new(threads: usize) -> Result<Self> {
        let threads = resolve_threads(threads);
        let pool = if threads > 1 {
            Some(
                ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .thread_name(|i| format!("packrat-worker-{i}"))
                    .build()
                    .map_err(|e| Error::Other(format!("cannot start worker threads: {e}")))?,
            )
        } else {
            None
        };
        Ok(Self {
            pool,
            queue: VecDeque::new(),
            window: threads * 2,
        })
    }

    pub fn threads(&self) -> usize {
        self.pool.as_ref().map_or(1, |p| p.current_num_threads())
    }

    /// Queues a job; if the window is full the oldest result is delivered to `sink` first.
    pub fn submit(
        &mut self,
        job: impl FnOnce() -> T + Send + 'static,
        sink: &mut dyn FnMut(T) -> Result<()>,
    ) -> Result<()> {
        self.make_room(sink)?;
        match &self.pool {
            Some(pool) => {
                let (tx, rx) = sync_channel(1);
                pool.spawn(move || {
                    let _ = tx.send(job());
                });
                self.queue.push_back(Slot::Pending(rx));
            }
            None => self.queue.push_back(Slot::Ready(job())),
        }
        Ok(())
    }

    /// Queues a value that needs no work but must keep its place in the order.
    pub fn push_ready(&mut self, value: T, sink: &mut dyn FnMut(T) -> Result<()>) -> Result<()> {
        self.make_room(sink)?;
        self.queue.push_back(Slot::Ready(value));
        Ok(())
    }

    /// Delivers every outstanding result in order.
    pub fn finish(&mut self, sink: &mut dyn FnMut(T) -> Result<()>) -> Result<()> {
        while !self.queue.is_empty() {
            self.pop(sink)?;
        }
        Ok(())
    }

    fn make_room(&mut self, sink: &mut dyn FnMut(T) -> Result<()>) -> Result<()> {
        while self.queue.len() >= self.window {
            self.pop(sink)?;
        }
        Ok(())
    }

    fn pop(&mut self, sink: &mut dyn FnMut(T) -> Result<()>) -> Result<()> {
        let value = match self.queue.pop_front() {
            Some(Slot::Ready(v)) => v,
            Some(Slot::Pending(rx)) => rx.recv().map_err(|_| Error::Other("a worker thread panicked".into()))?,
            None => return Ok(()),
        };
        sink(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_keep_submission_order() {
        for threads in [1, 4] {
            let mut pool = OrderedPool::<u32>::new(threads).unwrap();
            let mut got = Vec::new();
            for i in 0..200u32 {
                // later jobs finish first
                let delay = if i % 7 == 0 { 3 } else { 0 };
                pool.submit(
                    move || {
                        std::thread::sleep(std::time::Duration::from_millis(delay));
                        i
                    },
                    &mut |v| {
                        got.push(v);
                        Ok(())
                    },
                )
                .unwrap();
            }
            pool.finish(&mut |v| {
                got.push(v);
                Ok(())
            })
            .unwrap();
            assert_eq!(got, (0..200).collect::<Vec<_>>());
        }
    }
}
