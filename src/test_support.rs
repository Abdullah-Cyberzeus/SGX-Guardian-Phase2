use once_cell::sync::Lazy;
use tokio::sync::{Mutex, MutexGuard};

static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub async fn async_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.lock().await
}

pub fn blocking_env_lock() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK.blocking_lock()
}

/// Serializes every test that binds the fixed `REGISTRY_SYNC_PORT`.
///
/// `nebula::registry_sync`, `did::tests::resolver_tests` and `api::tests` all
/// stand up a mock CA on that one hardcoded port. Within a single test binary
/// they are otherwise free to overlap — and a listener that is still closing
/// when the next test binds produces a flaky `AddrInUse`. One lock shared by
/// all three call sites is what makes that impossible, so it lives here rather
/// than privately inside any one of them.
static REGISTRY_PORT_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub async fn registry_port_lock() -> MutexGuard<'static, ()> {
    REGISTRY_PORT_LOCK.lock().await
}
