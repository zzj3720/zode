use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};

use crate::runtime::ports::{Clock, TimerArm, TimerKey, TimerPort, TimerPortError};

struct SleepTimerInner {
    due_tx: Option<UnboundedSender<TimerArm>>,
    arms: HashMap<String, JoinHandle<()>>,
}

pub struct SleepTimer {
    clock: Arc<dyn Clock>,
    inner: Mutex<SleepTimerInner>,
    shutdown: AtomicBool,
}

impl SleepTimer {
    pub fn new(clock: Arc<dyn Clock>, due_tx: UnboundedSender<TimerArm>) -> Self {
        Self {
            clock,
            inner: Mutex::new(SleepTimerInner {
                due_tx: Some(due_tx),
                arms: HashMap::new(),
            }),
            shutdown: AtomicBool::new(false),
        }
    }
}

impl TimerPort for SleepTimer {
    fn arm(&self, arm: TimerArm) -> Result<(), TimerPortError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(TimerPortError::Shutdown);
        }
        let delay_ms = arm.deadline_ms.saturating_sub(self.clock.now_ms());
        let delay = Duration::from_millis(u64::try_from(delay_ms).unwrap_or(0));
        let clock = self.clock.clone();
        let mut inner = self.inner.lock().map_err(|_| TimerPortError::Backend)?;
        let Some(tx) = inner.due_tx.clone() else {
            return Err(TimerPortError::Shutdown);
        };
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(TimerPortError::Shutdown);
        }
        let session_id = arm.session_id.clone();
        let handle = tokio::spawn(async move {
            clock.sleep(delay).await;
            let _ = tx.send(arm);
        });
        if let Some(previous) = inner.arms.insert(session_id, handle) {
            previous.abort();
        }
        Ok(())
    }

    fn cancel(&self, key: &TimerKey) -> Result<(), TimerPortError> {
        let mut inner = self.inner.lock().map_err(|_| TimerPortError::Backend)?;
        if let Some(handle) = inner.arms.remove(&key.session_id) {
            handle.abort();
        }
        Ok(())
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Ok(mut inner) = self.inner.lock() {
            inner.due_tx.take();
            for (_, handle) in inner.arms.drain() {
                handle.abort();
            }
        }
    }
}
