//! Background workers usable from any GUI event loop. Only the frontend renders events.
use crate::{
    AiOptions, AnalysisOutcome, AnalysisRequest, AnalysisService, AnalysisSession, QueryOptions,
    RecordSelection, TaskStatus,
    core::execution::{CancellationToken, ExecutionContext, ProgressEvent, is_cancelled},
};
use anyhow::{Result, anyhow};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
};

pub type TaskId = u64;
static NEXT_TASK: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub enum TaskEvent {
    Status {
        task_id: TaskId,
        status: TaskStatus,
    },
    Progress {
        task_id: TaskId,
        progress: ProgressEvent,
    },
}
impl TaskEvent {
    pub fn task_id(&self) -> TaskId {
        match self {
            Self::Status { task_id, .. } | Self::Progress { task_id, .. } => *task_id,
        }
    }
}

pub struct TaskHandle<T> {
    pub id: TaskId,
    pub events: Receiver<TaskEvent>,
    token: CancellationToken,
    state: Arc<Mutex<TaskStatus>>,
    event_sender: Sender<TaskEvent>,
    result: Receiver<Result<T>>,
    worker: thread::JoinHandle<()>,
}
impl<T> TaskHandle<T> {
    pub fn status(&self) -> TaskStatus {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn cancel(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if *state == TaskStatus::Running {
            *state = TaskStatus::Cancelling;
            self.token.cancel();
            let _ = self.event_sender.send(TaskEvent::Status {
                task_id: self.id,
                status: TaskStatus::Cancelling,
            });
        }
    }
    pub fn wait(self) -> Result<T> {
        let result = self
            .result
            .recv()
            .map_err(|_| anyhow!("后台任务未返回结果"))?;
        self.worker
            .join()
            .map_err(|_| anyhow!("后台任务退出失败"))?;
        result
    }
    /// Take the result once without blocking the GUI. Do not call wait after taking it.
    pub fn try_result(&self) -> Result<Option<Result<T>>> {
        match self.result.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(anyhow!("后台任务结果通道已关闭")),
        }
    }
}

pub fn spawn_analysis(request: AnalysisRequest) -> TaskHandle<AnalysisOutcome> {
    spawn(
        move |ctx| AnalysisService::execute(&request, ctx),
        |outcome| outcome.status,
    )
}
pub fn spawn_query(session: AnalysisSession, query: QueryOptions) -> TaskHandle<RecordSelection> {
    spawn(
        move |ctx| session.query(&query, ctx),
        |_| TaskStatus::Completed,
    )
}
pub fn spawn_ai(
    session: AnalysisSession,
    options: AiOptions,
    selection: Option<RecordSelection>,
) -> TaskHandle<AnalysisOutcome> {
    spawn(
        move |ctx| AnalysisService::analyze_ai(&session, &options, selection.as_ref(), ctx),
        |outcome| outcome.status,
    )
}

/// Run another application operation (for example export or settings check) on
/// the same task transport. The operation should honor the supplied context.
pub fn spawn_operation<T: Send + 'static>(
    operation: impl FnOnce(&ExecutionContext) -> Result<T> + Send + 'static,
) -> TaskHandle<T> {
    spawn(operation, |_| TaskStatus::Completed)
}

fn spawn<T: Send + 'static>(
    run: impl FnOnce(&ExecutionContext) -> Result<T> + Send + 'static,
    success: impl FnOnce(&T) -> TaskStatus + Send + 'static,
) -> TaskHandle<T> {
    let id = NEXT_TASK.fetch_add(1, Ordering::Relaxed);
    let token = CancellationToken::default();
    let state = Arc::new(Mutex::new(TaskStatus::Running));
    let (event_sender, events) = mpsc::channel();
    let (result_sender, result) = mpsc::channel();
    let sender = event_sender.clone();
    let progress_sender = sender.clone();
    let worker_state = state.clone();
    let ctx = ExecutionContext::new(token.clone(), move |progress| {
        let _ = progress_sender.send(TaskEvent::Progress {
            task_id: id,
            progress,
        });
    });
    // Send Running before making the handle available, so cancel cannot reorder it.
    let _ = sender.send(TaskEvent::Status {
        task_id: id,
        status: TaskStatus::Running,
    });
    let worker = thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| run(&ctx)))
            .unwrap_or_else(|_| Err(anyhow!("后台分析任务异常退出")));
        let status = match &result {
            Ok(value) => success(value),
            Err(error) if is_cancelled(error) => TaskStatus::Cancelled,
            Err(_) => TaskStatus::Failed,
        };
        let _ = result_sender.send(result);
        {
            let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
            *state = status;
            let _ = sender.send(TaskEvent::Status {
                task_id: id,
                status,
            });
        }
    });
    TaskHandle {
        id,
        events,
        token,
        state,
        event_sender,
        result,
        worker,
    }
}
