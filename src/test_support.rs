use once_cell::sync::Lazy;
use tokio::sync::{Mutex, MutexGuard};

static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub async fn async_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().await
}

pub fn blocking_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.blocking_lock()
}
