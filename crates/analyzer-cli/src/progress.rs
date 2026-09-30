use std::{
    io::{self, IsTerminal, Write},
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

enum Update {
    Batch(usize, usize),
    Stop,
}

/// Draw only on an interactive stderr; stdout remains suitable for JSON and pipes.
pub struct AiProgress {
    worker: Option<(Sender<Update>, JoinHandle<()>)>,
    started: Instant,
}

impl AiProgress {
    pub fn start() -> Self {
        let started = Instant::now();
        let mut progress = Self {
            worker: None,
            started,
        };
        if !io::stderr().is_terminal() || std::env::var("TERM").is_ok_and(|term| term == "dumb") {
            return progress;
        }
        let (sender, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("ai-progress".into())
            .spawn(move || {
                let frames = ['|', '/', '-', '\\'];
                let mut frame = 0;
                let mut stage = "准备证据".to_owned();
                let mut width: usize = 0;
                loop {
                    let line = format!(
                        "{} AI 分析中 | {} | {}s",
                        frames[frame % frames.len()],
                        stage,
                        started.elapsed().as_secs()
                    );
                    // Output contains only ASCII and Chinese, whose cell widths are 1 and 2.
                    let next_width = line
                        .chars()
                        .map(|c| if c.is_ascii() { 1 } else { 2 })
                        .sum::<usize>();
                    let mut stderr = io::stderr().lock();
                    if write!(
                        stderr,
                        "\r{line}{}",
                        " ".repeat(width.saturating_sub(next_width))
                    )
                    .and_then(|_| stderr.flush())
                    .is_err()
                    {
                        break;
                    }
                    drop(stderr);
                    width = next_width;
                    frame += 1;
                    match receiver.recv_timeout(Duration::from_millis(120)) {
                        Ok(Update::Batch(index, total)) => {
                            stage = format!("批次 {index}/{total}");
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Ok(Update::Stop) | Err(RecvTimeoutError::Disconnected) => {
                            let mut stderr = io::stderr().lock();
                            let _ = write!(stderr, "\r{}\r", " ".repeat(width));
                            let _ = stderr.flush();
                            break;
                        }
                    }
                }
            });
        if let Ok(worker) = worker {
            progress.worker = Some((sender, worker));
        }
        progress
    }

    pub fn batch(&self, index: usize, total: usize) {
        if let Some((sender, _)) = &self.worker {
            let _ = sender.send(Update::Batch(index, total));
        }
    }

    pub fn finish(mut self, success: bool) {
        let visible = self.worker.is_some();
        self.stop();
        if visible {
            eprintln!(
                "AI 分析{}（耗时 {} 秒）",
                if success { "完成" } else { "未完成" },
                self.started.elapsed().as_secs()
            );
        }
    }

    fn stop(&mut self) {
        if let Some((sender, worker)) = self.worker.take() {
            let _ = sender.send(Update::Stop);
            let _ = worker.join();
        }
    }
}

impl Drop for AiProgress {
    fn drop(&mut self) {
        self.stop();
    }
}
