use anyhow::{anyhow, Result};
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

const USERS_FILE: &str = "users.json";
const SESSIONS_FILE: &str = "sessions.json";
const DEVICES_FILE: &str = "devices.json";
const PAIRING_FILE: &str = "pairing.json";
const OIDC_TRANSACTIONS_FILE: &str = "oidc_transactions.json";

static GLOBAL_ADMIN_STORES: OnceCell<Arc<AdminStores>> = OnceCell::new();

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Owner,
    Admin,
    Member,
}

impl UserRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct User {
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub pw_hash: String,
    pub role: UserRole,
    /// Server-authoritative API permissions. Empty legacy records are
    /// resolved to the role defaults when a session is issued or checked.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Circle IDs this browser account may access. Empty is unrestricted for
    /// legacy administrative accounts and deny-all for member accounts.
    #[serde(default)]
    pub circle_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_registration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<String>,
    pub created_at: String,
    #[serde(default = "default_user_status")]
    pub status: String,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_at: Option<i64>,
    /// Stable OIDC `sub` claim from the identity provider that created this
    /// account (e.g. Cylenium). This, not email, is the durable identity
    /// key for SSO logins — email can change or be reassigned upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sub: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub pw_hash: String,
    pub role: UserRole,
    pub oidc_sub: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewMemberRegistration {
    pub name: String,
    pub email: String,
    pub pw_hash: String,
    pub circle_id: String,
    pub browser_registration_id: String,
    pub guardian_fingerprint: String,
    pub registration_expires_at: i64,
    pub invite_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionRec {
    pub jti: String,
    pub user_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PairedDevice {
    #[serde(alias = "deviceId")]
    pub device_id: String,
    pub serial: String,
    pub did: String,
    #[serde(alias = "ownerUserId")]
    pub owner_user_id: String,
    #[serde(default, alias = "pairedAt")]
    pub paired_at: String,
    #[serde(
        default,
        alias = "reactivatedAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub reactivated_at: Option<String>,
    #[serde(default, alias = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub status: String,
    #[serde(default, alias = "nodeId", skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PairingChallengeRecord {
    pub serial: String,
    pub challenge: String,
    pub nonce: String,
    pub exp: i64,
    pub owner_user_id: String,
    pub api_consumed: bool,
    pub bootstrap_consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OidcTransactionRecord {
    pub state: String,
    pub nonce: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create(&self, new_user: NewUser) -> Result<User>;
    async fn create_initial_owner(&self, new_user: NewUser) -> Result<User>;
    async fn count(&self) -> Result<usize>;
    async fn find_by_id(&self, user_id: &str) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_oidc_sub(&self, oidc_sub: &str) -> Result<Option<User>>;
    /// Backfills `oidc_sub` on a pre-existing (e.g. password-created) user
    /// the first time they complete an SSO login with a matching email, so
    /// subsequent logins can be keyed by `sub` instead of email.
    async fn link_oidc_sub(&self, user_id: &str, oidc_sub: &str) -> Result<User>;
    async fn prepare_login(&self, email: &str, now: i64, window_secs: i64) -> Result<Option<User>>;
    async fn record_login_failure(
        &self,
        email: &str,
        now: i64,
        threshold: u32,
        window_secs: i64,
        lockout_secs: i64,
    ) -> Result<Option<User>>;
    async fn reset_login_failures(&self, email: &str) -> Result<Option<User>>;
    /// Atomically creates a member or reactivates the same inactive member
    /// during a verified rejoin. Active accounts cannot be overwritten.
    async fn create_or_reactivate_member(&self, member: NewMemberRegistration) -> Result<User>;
    async fn revoke_browser_registration(
        &self,
        user_id: &str,
        registration_id: &str,
    ) -> Result<User>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn put(&self, session: SessionRec) -> Result<()>;
    async fn get(&self, jti: &str) -> Result<Option<SessionRec>>;
    async fn revoke(&self, jti: &str) -> Result<()>;
    /// Revoke every active browser session belonging to one local account.
    async fn revoke_all_for_user(&self, user_id: &str) -> Result<usize>;
    async fn is_revoked(&self, jti: &str) -> Result<bool>;
}

#[async_trait]
pub trait DeviceStore: Send + Sync {
    async fn upsert(&self, device: PairedDevice) -> Result<()>;
    async fn get(&self, device_id: &str) -> Result<Option<PairedDevice>>;
    async fn get_by_did(&self, did: &str) -> Result<Option<PairedDevice>>;
    async fn list(&self, owner_user_id: &str) -> Result<Vec<PairedDevice>>;
    async fn list_all(&self) -> Result<Vec<PairedDevice>>;
    async fn list_all_records(&self) -> Result<Vec<PairedDevice>>;
    async fn list_unpaired(&self) -> Result<Vec<PairedDevice>>;
    async fn unbind(&self, owner_user_id: &str, device_id: &str) -> Result<()>;
}

#[async_trait]
pub trait PairingStore: Send + Sync {
    async fn put(&self, record: PairingChallengeRecord) -> Result<()>;
    async fn get(&self, serial: &str, nonce: &str) -> Result<Option<PairingChallengeRecord>>;
    async fn list(&self) -> Result<Vec<PairingChallengeRecord>>;
}

/// Server-side record of a pending Cylenium OIDC authorization request.
///
/// `state` and `nonce` are generated here (not by the client) so the
/// callback handler can bind the returned id_token back to the exact
/// `/authorize` request SG-X issued, instead of trusting nonce/state values
/// supplied in the callback body.
#[async_trait]
pub trait OidcTransactionStore: Send + Sync {
    async fn put(&self, record: OidcTransactionRecord) -> Result<()>;
    /// Atomically look up and mark single-use. Returns `None` for an
    /// unknown, already-used, or expired `state` so replay of a callback
    /// cannot succeed twice.
    async fn consume(&self, state: &str) -> Result<Option<OidcTransactionRecord>>;
}

#[derive(Clone)]
pub struct AdminStores {
    pub users: Arc<dyn UserStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub devices: Arc<dyn DeviceStore>,
    pub pairings: Arc<dyn PairingStore>,
    pub oidc_transactions: Arc<dyn OidcTransactionStore>,
    admin_dir: PathBuf,
    devices_file: Arc<JsonStoreFile<Vec<PairedDevice>>>,
    pairings_file: Arc<JsonStoreFile<Vec<PairingChallengeRecord>>>,
    bootstrap_sync_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Copy)]
struct BootstrapSyncMatch<'a> {
    serial: Option<&'a str>,
    device_id: Option<&'a str>,
    did: Option<&'a str>,
    owner_user_id: Option<&'a str>,
    node_id: Option<&'a str>,
}

impl AdminStores {
    pub fn new<P: AsRef<Path>>(admin_dir: P) -> Arc<Self> {
        let admin_dir = admin_dir.as_ref().to_path_buf();
        let devices_file = Arc::new(JsonStoreFile::new(admin_dir.join(DEVICES_FILE)));
        let pairings_file = Arc::new(JsonStoreFile::new(admin_dir.join(PAIRING_FILE)));
        Arc::new(Self {
            users: Arc::new(JsonUserStore::new(admin_dir.join(USERS_FILE))),
            sessions: Arc::new(JsonSessionStore::new(admin_dir.join(SESSIONS_FILE))),
            devices: Arc::new(JsonDeviceStore::new(devices_file.clone())),
            pairings: Arc::new(JsonPairingStore::new(pairings_file.clone())),
            oidc_transactions: Arc::new(JsonOidcTransactionStore::new(
                admin_dir.join(OIDC_TRANSACTIONS_FILE),
            )),
            admin_dir,
            devices_file,
            pairings_file,
            bootstrap_sync_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn admin_dir(&self) -> &Path {
        &self.admin_dir
    }

    pub async fn finalize_bootstrap(
        &self,
        pairing: &crate::api::auth::pairing::AuthorizedPairing,
    ) -> Result<()> {
        self.sync_bootstrap_completion(BootstrapSyncMatch {
            serial: Some(pairing.serial.as_str()),
            device_id: Some(pairing.device_id.as_str()),
            did: Some(pairing.device_did.as_str()),
            owner_user_id: Some(pairing.owner_user_id.as_str()),
            node_id: Some(pairing.node_id.as_str()),
        })
        .await
    }

    pub async fn sync_bootstrap_by_identity(
        &self,
        serial: Option<&str>,
        device_id: Option<&str>,
        did: Option<&str>,
        owner_user_id: Option<&str>,
        node_id: Option<&str>,
    ) -> Result<()> {
        self.sync_bootstrap_completion(BootstrapSyncMatch {
            serial,
            device_id,
            did,
            owner_user_id,
            node_id,
        })
        .await
    }

    async fn sync_bootstrap_completion(&self, matcher: BootstrapSyncMatch<'_>) -> Result<()> {
        let _sync_guard = self.bootstrap_sync_lock.lock().await;
        let _devices_guard = self.devices_file.lock.write().await;
        let _pairings_guard = self.pairings_file.lock.write().await;

        let mut devices = self.devices_file.read_unlocked().await?;
        let mut pairings = self.pairings_file.read_unlocked().await?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut changed = false;

        if let Some(index) = find_matching_device_index(&devices, matcher) {
            let device = &mut devices[index];
            if let Some(device_id) = matcher.device_id {
                if device.device_id != device_id {
                    device.device_id = device_id.to_string();
                    changed = true;
                }
            }
            if let Some(serial) = matcher.serial {
                if device.serial != serial {
                    device.serial = serial.to_string();
                    changed = true;
                }
            }
            if let Some(did) = matcher.did {
                if device.did != did {
                    device.did = did.to_string();
                    changed = true;
                }
            }
            if let Some(owner_user_id) = matcher.owner_user_id {
                if device.owner_user_id != owner_user_id {
                    device.owner_user_id = owner_user_id.to_string();
                    changed = true;
                }
            }
            if device.status != "active" {
                device.status = "active".into();
                changed = true;
            }
            if let Some(node_id) = matcher.node_id {
                if device.node_id.as_deref() != Some(node_id) {
                    device.node_id = Some(node_id.to_string());
                    changed = true;
                }
            }
            if device.paired_at.trim().is_empty() {
                device.paired_at = now.clone();
                changed = true;
            }
        }

        if let Some(index) = find_matching_pairing_index(&pairings, matcher) {
            let record = &mut pairings[index];
            if let Some(serial) = matcher.serial {
                if record.serial != serial {
                    record.serial = serial.to_string();
                    changed = true;
                }
            }
            if let Some(owner_user_id) = matcher.owner_user_id {
                if record.owner_user_id != owner_user_id {
                    record.owner_user_id = owner_user_id.to_string();
                    changed = true;
                }
            }
            if !record.bootstrap_consumed {
                record.bootstrap_consumed = true;
                changed = true;
            }
            if let Some(device_id) = matcher.device_id {
                if record.device_id.as_deref() != Some(device_id) {
                    record.device_id = Some(device_id.to_string());
                    changed = true;
                }
            }
            if let Some(did) = matcher.did {
                if record.did.as_deref() != Some(did) {
                    record.did = Some(did.to_string());
                    changed = true;
                }
            }
            if let Some(node_id) = matcher.node_id {
                if record.node_id.as_deref() != Some(node_id) {
                    record.node_id = Some(node_id.to_string());
                    changed = true;
                }
            }
            if record.bound_at.is_none() {
                record.bound_at = Some(now.clone());
                changed = true;
            }
        }

        if !changed {
            return Ok(());
        }

        write_store_pair_atomically(
            &self.devices_file.path,
            &devices,
            &self.pairings_file.path,
            &pairings,
        )
        .await?;
        Ok(())
    }
}

pub fn install_global_admin_stores(stores: Arc<AdminStores>) {
    let _ = GLOBAL_ADMIN_STORES.set(stores);
}

pub fn global_admin_stores() -> Option<Arc<AdminStores>> {
    GLOBAL_ADMIN_STORES.get().cloned()
}

async fn write_store_pair_atomically<A, B>(
    first_path: &Path,
    first_value: &A,
    second_path: &Path,
    second_value: &B,
) -> Result<()>
where
    A: Serialize,
    B: Serialize,
{
    let first_tmp = stage_json_store_write(first_path, first_value).await?;
    let second_tmp = stage_json_store_write(second_path, second_value).await?;

    if let Err(err) = commit_staged_json_store_write(&first_tmp, first_path).await {
        let _ = fs::remove_file(&first_tmp).await;
        let _ = fs::remove_file(&second_tmp).await;
        return Err(err);
    }

    if let Err(err) = commit_staged_json_store_write(&second_tmp, second_path).await {
        let _ = fs::remove_file(&second_tmp).await;
        return Err(err);
    }

    Ok(())
}

async fn stage_json_store_write<T: Serialize>(path: &Path, value: &T) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| anyhow!("create {}: {}", parent.display(), e))?;
    }

    let serialized = serde_json::to_vec_pretty(value)
        .map_err(|e| anyhow!("serialize {}: {}", path.display(), e))?;
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("store"),
        Uuid::new_v4()
    ));

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp)
        .await
        .map_err(|e| anyhow!("open {}: {}", tmp.display(), e))?;
    file.write_all(&serialized)
        .await
        .map_err(|e| anyhow!("write {}: {}", tmp.display(), e))?;
    file.sync_all()
        .await
        .map_err(|e| anyhow!("sync {}: {}", tmp.display(), e))?;
    drop(file);

    Ok(tmp)
}

async fn commit_staged_json_store_write(tmp: &Path, path: &Path) -> Result<()> {
    fs::rename(tmp, path)
        .await
        .map_err(|e| anyhow!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| anyhow!("chmod {}: {}", path.display(), e))?;
    }
    Ok(())
}

struct JsonStoreFile<T> {
    path: PathBuf,
    lock: RwLock<()>,
    _marker: PhantomData<T>,
}

impl<T> JsonStoreFile<T>
where
    T: Default + DeserializeOwned + Serialize,
{
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: RwLock::new(()),
            _marker: PhantomData,
        }
    }

    async fn read(&self) -> Result<T> {
        let _guard = self.lock.read().await;
        self.read_unlocked().await
    }

    async fn mutate<R>(&self, mutator: impl FnOnce(&mut T) -> Result<R>) -> Result<R> {
        let _guard = self.lock.write().await;
        let mut value = self.read_unlocked().await?;
        let result = mutator(&mut value)?;
        self.write_unlocked(&value).await?;
        Ok(result)
    }

    async fn read_unlocked(&self) -> Result<T> {
        match fs::read(&self.path).await {
            Ok(bytes) if bytes.is_empty() => Ok(T::default()),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("parse {}: {}", self.path.display(), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(anyhow!("read {}: {}", self.path.display(), e)),
        }
    }

    async fn write_unlocked(&self, value: &T) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| anyhow!("create {}: {}", parent.display(), e))?;
        }
        let serialized = serde_json::to_vec_pretty(value)
            .map_err(|e| anyhow!("serialize {}: {}", self.path.display(), e))?;
        let tmp = self.path.with_file_name(format!(
            "{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("store"),
            Uuid::new_v4()
        ));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .await
            .map_err(|e| anyhow!("open {}: {}", tmp.display(), e))?;
        file.write_all(&serialized)
            .await
            .map_err(|e| anyhow!("write {}: {}", tmp.display(), e))?;
        file.sync_all()
            .await
            .map_err(|e| anyhow!("sync {}: {}", tmp.display(), e))?;
        drop(file);
        fs::rename(&tmp, &self.path)
            .await
            .map_err(|e| anyhow!("rename {} -> {}: {}", tmp.display(), self.path.display(), e))?;
        #[cfg(unix)]
        {
            fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| anyhow!("chmod {}: {}", self.path.display(), e))?;
        }
        Ok(())
    }
}

struct JsonUserStore {
    file: JsonStoreFile<Vec<User>>,
}

impl JsonUserStore {
    fn new(path: PathBuf) -> Self {
        Self {
            file: JsonStoreFile::new(path),
        }
    }

    fn build_user(new_user: NewUser) -> User {
        User {
            user_id: Uuid::new_v4().to_string(),
            name: new_user.name.trim().to_string(),
            email: normalize_email(&new_user.email),
            pw_hash: new_user.pw_hash,
            role: new_user.role,
            scopes: crate::api::auth::authorization::default_scopes(new_user.role.as_str()),
            circle_ids: Vec::new(),
            browser_registration_id: None,
            guardian_fingerprint: None,
            registration_expires_at: None,
            invite_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            status: default_user_status(),
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            oidc_sub: new_user.oidc_sub,
        }
    }

    fn clear_login_failures(user: &mut User) {
        user.failed_attempts = 0;
        user.locked_until = None;
        user.last_failed_at = None;
    }

    fn reconcile_login_state(user: &mut User, now: i64, window_secs: i64) {
        let window_secs = window_secs.max(1);
        let lockout_expired = user
            .locked_until
            .is_some_and(|locked_until| locked_until <= now);
        let window_expired = match user.last_failed_at {
            Some(last_failed_at) => now.saturating_sub(last_failed_at) >= window_secs,
            None => true,
        };

        if lockout_expired || (user.failed_attempts > 0 && window_expired) {
            Self::clear_login_failures(user);
        }
    }
}

#[async_trait]
impl UserStore for JsonUserStore {
    async fn create(&self, new_user: NewUser) -> Result<User> {
        self.file
            .mutate(move |users| {
                let normalized_email = normalize_email(&new_user.email);
                if users.iter().any(|user| user.email == normalized_email) {
                    return Err(anyhow!("user already exists"));
                }
                let user = Self::build_user(new_user);
                users.push(user.clone());
                Ok(user)
            })
            .await
    }

    async fn create_initial_owner(&self, new_user: NewUser) -> Result<User> {
        self.file
            .mutate(move |users| {
                if !users.is_empty() {
                    return Err(anyhow!(
                        "signup is only allowed before the first user is created"
                    ));
                }
                let normalized_email = normalize_email(&new_user.email);
                if users.iter().any(|user| user.email == normalized_email) {
                    return Err(anyhow!("user already exists"));
                }
                let user = Self::build_user(new_user);
                users.push(user.clone());
                Ok(user)
            })
            .await
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.file.read().await?.len())
    }

    async fn find_by_id(&self, user_id: &str) -> Result<Option<User>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|user| user.user_id == user_id))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let email = normalize_email(email);
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|user| user.email == email))
    }

    async fn find_by_oidc_sub(&self, oidc_sub: &str) -> Result<Option<User>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|user| user.oidc_sub.as_deref() == Some(oidc_sub)))
    }

    async fn link_oidc_sub(&self, user_id: &str, oidc_sub: &str) -> Result<User> {
        let user_id = user_id.to_string();
        let oidc_sub = oidc_sub.to_string();
        self.file
            .mutate(move |users| {
                let user = users
                    .iter_mut()
                    .find(|user| user.user_id == user_id)
                    .ok_or_else(|| anyhow!("user not found"))?;
                user.oidc_sub = Some(oidc_sub);
                Ok(user.clone())
            })
            .await
    }

    async fn prepare_login(&self, email: &str, now: i64, window_secs: i64) -> Result<Option<User>> {
        let email = normalize_email(email);
        self.file
            .mutate(move |users| {
                let Some(user) = users.iter_mut().find(|user| user.email == email) else {
                    return Ok(None);
                };
                Self::reconcile_login_state(user, now, window_secs);
                Ok(Some(user.clone()))
            })
            .await
    }

    async fn record_login_failure(
        &self,
        email: &str,
        now: i64,
        threshold: u32,
        window_secs: i64,
        lockout_secs: i64,
    ) -> Result<Option<User>> {
        let email = normalize_email(email);
        let threshold = threshold.max(1);
        let lockout_secs = lockout_secs.max(1);
        self.file
            .mutate(move |users| {
                let Some(user) = users.iter_mut().find(|user| user.email == email) else {
                    return Ok(None);
                };
                Self::reconcile_login_state(user, now, window_secs);
                user.failed_attempts = user.failed_attempts.saturating_add(1);
                user.last_failed_at = Some(now);
                if user.failed_attempts >= threshold {
                    user.locked_until = Some(now.saturating_add(lockout_secs));
                }
                Ok(Some(user.clone()))
            })
            .await
    }

    async fn reset_login_failures(&self, email: &str) -> Result<Option<User>> {
        let email = normalize_email(email);
        self.file
            .mutate(move |users| {
                let Some(user) = users.iter_mut().find(|user| user.email == email) else {
                    return Ok(None);
                };
                Self::clear_login_failures(user);
                Ok(Some(user.clone()))
            })
            .await
    }

    async fn create_or_reactivate_member(&self, member: NewMemberRegistration) -> Result<User> {
        self.file
            .mutate(move |users| {
                let normalized_email = normalize_email(&member.email);
                if let Some(existing) = users.iter_mut().find(|user| user.email == normalized_email) {
                    let registration_still_valid = existing.status == "active"
                        && existing
                            .registration_expires_at
                            .is_some_and(|expiry| expiry > chrono::Utc::now().timestamp())
                        && existing.guardian_fingerprint.as_deref()
                            == Some(member.guardian_fingerprint.as_str());
                    if existing.role != UserRole::Member || registration_still_valid {
                        return Err(anyhow!("user already exists"));
                    }
                    existing.name = member.name.trim().to_string();
                    existing.pw_hash = member.pw_hash;
                    existing.scopes = crate::api::auth::authorization::default_scopes("member");
                    existing.circle_ids = vec![member.circle_id];
                    existing.browser_registration_id = Some(member.browser_registration_id);
                    existing.guardian_fingerprint = Some(member.guardian_fingerprint);
                    existing.registration_expires_at = Some(member.registration_expires_at);
                    existing.invite_id = Some(member.invite_id);
                    existing.status = "active".into();
                    Self::clear_login_failures(existing);
                    return Ok(existing.clone());
                }

                let mut user = Self::build_user(NewUser {
                    name: member.name,
                    email: normalized_email,
                    pw_hash: member.pw_hash,
                    role: UserRole::Member,
                    oidc_sub: None,
                });
                user.circle_ids = vec![member.circle_id];
                user.browser_registration_id = Some(member.browser_registration_id);
                user.guardian_fingerprint = Some(member.guardian_fingerprint);
                user.registration_expires_at = Some(member.registration_expires_at);
                user.invite_id = Some(member.invite_id);
                users.push(user.clone());
                Ok(user)
            })
            .await
    }

    async fn revoke_browser_registration(
        &self,
        user_id: &str,
        registration_id: &str,
    ) -> Result<User> {
        let user_id = user_id.to_string();
        let registration_id = registration_id.to_string();
        self.file
            .mutate(move |users| {
                let user = users
                    .iter_mut()
                    .find(|user| user.user_id == user_id)
                    .ok_or_else(|| anyhow!("user not found"))?;
                if user.browser_registration_id.as_deref() != Some(registration_id.as_str()) {
                    return Err(anyhow!("browser registration not found"));
                }
                user.status = "inactive".into();
                Ok(user.clone())
            })
            .await
    }
}

struct JsonSessionStore {
    file: JsonStoreFile<Vec<SessionRec>>,
}

impl JsonSessionStore {
    fn new(path: PathBuf) -> Self {
        Self {
            file: JsonStoreFile::new(path),
        }
    }
}

#[async_trait]
impl SessionStore for JsonSessionStore {
    async fn put(&self, session: SessionRec) -> Result<()> {
        self.file
            .mutate(move |sessions| {
                if let Some(existing) = sessions.iter_mut().find(|item| item.jti == session.jti) {
                    *existing = session.clone();
                } else {
                    sessions.push(session);
                }
                Ok(())
            })
            .await
    }

    async fn get(&self, jti: &str) -> Result<Option<SessionRec>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|session| session.jti == jti))
    }

    async fn revoke(&self, jti: &str) -> Result<()> {
        let target = jti.to_string();
        self.file
            .mutate(move |sessions| {
                let session = sessions
                    .iter_mut()
                    .find(|item| item.jti == target)
                    .ok_or_else(|| anyhow!("session not found"))?;
                session.revoked = true;
                Ok(())
            })
            .await
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Result<usize> {
        let target = user_id.to_string();
        self.file
            .mutate(move |sessions| {
                let mut revoked = 0usize;
                for session in sessions.iter_mut() {
                    if session.user_id == target && !session.revoked {
                        session.revoked = true;
                        revoked += 1;
                    }
                }
                Ok(revoked)
            })
            .await
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool> {
        Ok(self
            .get(jti)
            .await?
            .map(|session| session.revoked)
            .unwrap_or(false))
    }
}

fn find_matching_device_index(
    devices: &[PairedDevice],
    matcher: BootstrapSyncMatch<'_>,
) -> Option<usize> {
    devices
        .iter()
        .position(|device| {
            matcher
                .device_id
                .is_some_and(|device_id| device.device_id == device_id)
        })
        .or_else(|| {
            devices
                .iter()
                .position(|device| matcher.did.is_some_and(|did| device.did == did))
        })
        .or_else(|| {
            let mut matches = devices
                .iter()
                .enumerate()
                .filter(|(_, device)| {
                    matcher.serial.is_some_and(|serial| device.serial == serial)
                        && matcher
                            .owner_user_id
                            .is_none_or(|owner_user_id| device.owner_user_id == owner_user_id)
                })
                .map(|(index, _)| index);
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
}

fn find_matching_pairing_index(
    pairings: &[PairingChallengeRecord],
    matcher: BootstrapSyncMatch<'_>,
) -> Option<usize> {
    pairings
        .iter()
        .position(|record| {
            matcher.device_id.is_some_and(|device_id| {
                record.device_id.as_deref() == Some(device_id)
                    && matcher.serial.is_none_or(|serial| record.serial == serial)
            })
        })
        .or_else(|| {
            pairings.iter().position(|record| {
                matcher.did.is_some_and(|did| {
                    record.did.as_deref() == Some(did)
                        && matcher.serial.is_none_or(|serial| record.serial == serial)
                })
            })
        })
        .or_else(|| {
            let mut matches = pairings
                .iter()
                .enumerate()
                .filter(|(_, record)| {
                    matcher.serial.is_some_and(|serial| record.serial == serial)
                        && matcher
                            .owner_user_id
                            .is_none_or(|owner_user_id| record.owner_user_id == owner_user_id)
                })
                .map(|(index, _)| index);
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
}

struct JsonDeviceStore {
    file: Arc<JsonStoreFile<Vec<PairedDevice>>>,
}

impl JsonDeviceStore {
    fn new(file: Arc<JsonStoreFile<Vec<PairedDevice>>>) -> Self {
        Self { file }
    }
}

#[async_trait]
impl DeviceStore for JsonDeviceStore {
    async fn upsert(&self, device: PairedDevice) -> Result<()> {
        self.file
            .mutate(move |devices| {
                if let Some(existing) = devices
                    .iter_mut()
                    .find(|item| item.device_id == device.device_id)
                {
                    *existing = device.clone();
                } else {
                    devices.push(device);
                }
                Ok(())
            })
            .await
    }

    async fn get(&self, device_id: &str) -> Result<Option<PairedDevice>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|device| device.device_id == device_id))
    }

    async fn get_by_did(&self, did: &str) -> Result<Option<PairedDevice>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|device| device.did == did))
    }

    async fn list(&self, owner_user_id: &str) -> Result<Vec<PairedDevice>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .filter(|device| device.owner_user_id == owner_user_id && device.status != "unpaired")
            .collect())
    }

    async fn list_all(&self) -> Result<Vec<PairedDevice>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .filter(|device| device.status != "unpaired")
            .collect())
    }

    async fn list_all_records(&self) -> Result<Vec<PairedDevice>> {
        self.file.read().await
    }

    async fn list_unpaired(&self) -> Result<Vec<PairedDevice>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .filter(|device| device.status == "unpaired")
            .collect())
    }

    async fn unbind(&self, owner_user_id: &str, device_id: &str) -> Result<()> {
        let owner_user_id = owner_user_id.to_string();
        let device_id = device_id.to_string();
        self.file
            .mutate(move |devices| {
                let device = devices
                    .iter_mut()
                    .find(|device| {
                        device.owner_user_id == owner_user_id && device.device_id == device_id
                    })
                    .ok_or_else(|| anyhow!("device not found"))?;
                device.status = "unpaired".into();
                Ok(())
            })
            .await
    }
}

struct JsonPairingStore {
    file: Arc<JsonStoreFile<Vec<PairingChallengeRecord>>>,
}

impl JsonPairingStore {
    fn new(file: Arc<JsonStoreFile<Vec<PairingChallengeRecord>>>) -> Self {
        Self { file }
    }
}

#[async_trait]
impl PairingStore for JsonPairingStore {
    async fn put(&self, record: PairingChallengeRecord) -> Result<()> {
        self.file
            .mutate(move |records| {
                if let Some(existing) = records
                    .iter_mut()
                    .find(|item| item.serial == record.serial && item.nonce == record.nonce)
                {
                    *existing = record.clone();
                } else {
                    records.push(record);
                }
                Ok(())
            })
            .await
    }

    async fn get(&self, serial: &str, nonce: &str) -> Result<Option<PairingChallengeRecord>> {
        Ok(self
            .file
            .read()
            .await?
            .into_iter()
            .find(|item| item.serial == serial && item.nonce == nonce))
    }

    async fn list(&self) -> Result<Vec<PairingChallengeRecord>> {
        self.file.read().await
    }
}

struct JsonOidcTransactionStore {
    file: JsonStoreFile<Vec<OidcTransactionRecord>>,
}

impl JsonOidcTransactionStore {
    fn new(path: PathBuf) -> Self {
        Self {
            file: JsonStoreFile::new(path),
        }
    }
}

#[async_trait]
impl OidcTransactionStore for JsonOidcTransactionStore {
    async fn put(&self, record: OidcTransactionRecord) -> Result<()> {
        self.file
            .mutate(move |records| {
                if let Some(existing) = records.iter_mut().find(|item| item.state == record.state) {
                    *existing = record.clone();
                } else {
                    records.push(record);
                }
                Ok(())
            })
            .await
    }

    async fn consume(&self, state: &str) -> Result<Option<OidcTransactionRecord>> {
        let state = state.to_string();
        self.file
            .mutate(move |records| {
                let Some(record) = records.iter_mut().find(|item| item.state == state) else {
                    return Ok(None);
                };
                if record.used || record.expires_at <= chrono::Utc::now().timestamp() {
                    return Ok(None);
                }
                record.used = true;
                Ok(Some(record.clone()))
            })
            .await
    }
}

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn default_user_status() -> String {
    "active".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::pairing::{
        authorize_pairing_proof, build_pairing_proof, encode_challenge, issue_challenge,
        record_from_challenge, PairingUsage,
    };
    use crate::key_manager::KeyManager;
    use tempfile::TempDir;

    #[test]
    fn paired_device_accepts_api_field_names_and_missing_paired_at() {
        let device: PairedDevice = serde_json::from_value(serde_json::json!({
            "deviceId": "device-1",
            "serial": "GX-2024-TX-042-B9F3",
            "did": "did:guardian:device-1",
            "owner_user_id": "user-1",
            "status": "active",
            "nodeId": "nodeB"
        }))
        .expect("deserialize API-shaped stored device");

        assert_eq!(device.device_id, "device-1");
        assert_eq!(device.node_id.as_deref(), Some("nodeB"));
        assert_eq!(device.paired_at, "");
    }

    #[tokio::test]
    async fn user_store_round_trip_and_permissions() {
        let td = TempDir::new().expect("tempdir");
        let stores = AdminStores::new(td.path().join("admin"));
        let created = stores
            .users
            .create(NewUser {
                name: "Admin".into(),
                email: "ADMIN@example.com".into(),
                pw_hash: "hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("create user");
        assert_eq!(created.email, "admin@example.com");
        assert_eq!(stores.users.count().await.expect("count"), 1);
        assert!(stores
            .users
            .find_by_email("admin@example.com")
            .await
            .expect("find")
            .is_some());

        #[cfg(unix)]
        {
            let path = td.path().join("admin").join(USERS_FILE);
            let mode = std::fs::metadata(path)
                .expect("user file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn session_store_revokes_existing_session() {
        let td = TempDir::new().expect("tempdir");
        let stores = AdminStores::new(td.path().join("admin"));
        let session = SessionRec {
            jti: "jti-1".into(),
            user_id: "user-1".into(),
            issued_at: 1,
            expires_at: 2,
            revoked: false,
        };
        stores
            .sessions
            .put(session.clone())
            .await
            .expect("save session");
        assert!(!stores
            .sessions
            .is_revoked(&session.jti)
            .await
            .expect("revoked state"));

        stores
            .sessions
            .revoke(&session.jti)
            .await
            .expect("revoke session");
        assert!(stores
            .sessions
            .is_revoked(&session.jti)
            .await
            .expect("revoked state after revoke"));
    }

    #[tokio::test]
    async fn session_store_revokes_all_sessions_for_only_one_user() {
        let td = TempDir::new().expect("tempdir");
        let stores = AdminStores::new(td.path().join("admin"));
        for (jti, user_id) in [("one", "user-1"), ("two", "user-1"), ("other", "user-2")] {
            stores.sessions.put(SessionRec {
                jti: jti.into(),
                user_id: user_id.into(),
                issued_at: 1,
                expires_at: 2,
                revoked: false,
            }).await.expect("save session");
        }

        assert_eq!(stores.sessions.revoke_all_for_user("user-1").await.expect("revoke all"), 2);
        assert!(stores.sessions.is_revoked("one").await.expect("first state"));
        assert!(stores.sessions.is_revoked("two").await.expect("second state"));
        assert!(!stores.sessions.is_revoked("other").await.expect("other state"));
    }

    #[tokio::test]
    async fn initial_owner_signup_is_single_use() {
        let td = TempDir::new().expect("tempdir");
        let stores = AdminStores::new(td.path().join("admin"));
        stores
            .users
            .create_initial_owner(NewUser {
                name: "Admin".into(),
                email: "admin@example.com".into(),
                pw_hash: "hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("create initial owner");

        let err = stores
            .users
            .create_initial_owner(NewUser {
                name: "Another".into(),
                email: "other@example.com".into(),
                pw_hash: "hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect_err("reject second initial owner");
        assert!(err
            .to_string()
            .contains("signup is only allowed before the first user is created"));
    }

    #[tokio::test]
    async fn device_and_pairing_stores_round_trip() {
        let td = TempDir::new().expect("tempdir");
        let stores = AdminStores::new(td.path().join("admin"));
        let device = PairedDevice {
            device_id: "device-1".into(),
            serial: "GX-2024-TX-042-A9F3".into(),
            did: "did:guardian:test-device".into(),
            owner_user_id: "user-1".into(),
            paired_at: "2026-06-29T00:00:00Z".into(),
            reactivated_at: None,
            updated_at: None,
            status: "paired".into(),
            node_id: Some("nodeB".into()),
        };
        stores
            .devices
            .upsert(device.clone())
            .await
            .expect("store device");
        assert_eq!(
            stores
                .devices
                .get(&device.device_id)
                .await
                .expect("get device"),
            Some(device.clone())
        );
        assert_eq!(
            stores
                .devices
                .list(&device.owner_user_id)
                .await
                .expect("list devices"),
            vec![device.clone()]
        );

        let pairing = PairingChallengeRecord {
            serial: device.serial.clone(),
            challenge: "challenge".into(),
            nonce: "nonce".into(),
            exp: 12345,
            owner_user_id: device.owner_user_id.clone(),
            api_consumed: false,
            bootstrap_consumed: false,
            device_id: None,
            did: None,
            node_id: None,
            public_key: None,
            bound_at: None,
        };
        stores
            .pairings
            .put(pairing.clone())
            .await
            .expect("store pairing");
        assert_eq!(
            stores
                .pairings
                .get(&pairing.serial, &pairing.nonce)
                .await
                .expect("get pairing"),
            Some(pairing.clone())
        );
        assert_eq!(
            stores.pairings.list().await.expect("list pairings"),
            vec![pairing]
        );

        stores
            .devices
            .unbind(&device.owner_user_id, &device.device_id)
            .await
            .expect("unbind device");
        let unpaired = stores
            .devices
            .get(&device.device_id)
            .await
            .expect("device after unbind")
            .expect("unpaired device persists");
        assert_eq!(unpaired.status, "unpaired");
        assert!(stores
            .devices
            .list(&device.owner_user_id)
            .await
            .expect("list devices after unbind")
            .is_empty());
    }

    #[tokio::test]
    async fn user_store_persists_login_failures_and_lockout_state() {
        let td = TempDir::new().expect("tempdir");
        let admin_dir = td.path().join("admin");
        let stores = AdminStores::new(&admin_dir);
        stores
            .users
            .create_initial_owner(NewUser {
                name: "Admin".into(),
                email: "ADMIN@example.com".into(),
                pw_hash: "hash".into(),
                role: UserRole::Owner,
                oidc_sub: None,
            })
            .await
            .expect("create user");

        for attempt in 1..=5u32 {
            let user = stores
                .users
                .record_login_failure("ADMIN@example.com", attempt as i64, 5, 300, 60)
                .await
                .expect("record login failure")
                .expect("persisted user");
            assert_eq!(user.failed_attempts, attempt);
        }

        let reopened = AdminStores::new(&admin_dir);
        let persisted = reopened
            .users
            .find_by_email("admin@example.com")
            .await
            .expect("load user")
            .expect("persisted user");
        assert_eq!(persisted.failed_attempts, 5);
        assert_eq!(persisted.locked_until, Some(65));
    }

    #[tokio::test]
    async fn bootstrap_completion_syncs_device_and_pairing_state_idempotently() {
        let td = TempDir::new().expect("tempdir");
        let admin_dir = td.path().join("admin");
        let stores = AdminStores::new(&admin_dir);
        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load key manager"),
        );

        let challenge = issue_challenge("GX-2024-TX-042-A9F3", std::time::Duration::from_secs(300))
            .expect("issue challenge");
        stores
            .pairings
            .put(record_from_challenge(&challenge, "user-1"))
            .await
            .expect("store challenge");

        let proof = build_pairing_proof(
            &encode_challenge(&challenge).expect("encode challenge"),
            "nodeB",
            "did:guardian:test-node-b",
            &signer.pubkey_der().expect("pubkey"),
            signer,
        )
        .await
        .expect("build proof");

        let paired = authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Api)
            .await
            .expect("authorize api pairing");
        stores
            .devices
            .upsert(PairedDevice {
                device_id: paired.device_id.clone(),
                serial: paired.serial.clone(),
                did: paired.device_did.clone(),
                owner_user_id: paired.owner_user_id.clone(),
                paired_at: "2026-07-01T00:00:00Z".into(),
                reactivated_at: None,
                updated_at: None,
                status: "bootstrap_pending".into(),
                node_id: Some(paired.node_id.clone()),
            })
            .await
            .expect("store pending device");

        let bootstrapped =
            authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Bootstrap)
                .await
                .expect("authorize bootstrap pairing");

        let pairings_path = admin_dir.join(PAIRING_FILE);
        let mut stale_pairings: Vec<PairingChallengeRecord> =
            serde_json::from_slice(&std::fs::read(&pairings_path).expect("read pairings file"))
                .expect("parse pairings file");
        stale_pairings[0].bootstrap_consumed = false;
        std::fs::write(
            &pairings_path,
            serde_json::to_vec_pretty(&stale_pairings).expect("serialize stale pairings"),
        )
        .expect("write stale pairings");

        stores
            .finalize_bootstrap(&bootstrapped)
            .await
            .expect("finalize bootstrap");
        stores
            .finalize_bootstrap(&bootstrapped)
            .await
            .expect("finalize bootstrap again");

        let devices: Vec<PairedDevice> = serde_json::from_slice(
            &std::fs::read(admin_dir.join(DEVICES_FILE)).expect("read devices file"),
        )
        .expect("parse devices file");
        let pairings: Vec<PairingChallengeRecord> =
            serde_json::from_slice(&std::fs::read(pairings_path).expect("read pairings file"))
                .expect("parse pairings file");

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].status, "active");
        assert_eq!(devices[0].device_id, bootstrapped.device_id);
        assert_eq!(devices[0].did, bootstrapped.device_did);

        assert_eq!(pairings.len(), 1);
        assert!(pairings[0].bootstrap_consumed);
        assert_eq!(
            pairings[0].device_id.as_deref(),
            Some(bootstrapped.device_id.as_str())
        );
        assert_eq!(
            pairings[0].did.as_deref(),
            Some(bootstrapped.device_did.as_str())
        );
    }

    #[tokio::test]
    async fn bootstrap_completion_syncs_pending_state_by_device_id_only() {
        let td = TempDir::new().expect("tempdir");
        let admin_dir = td.path().join("admin");
        let stores = AdminStores::new(&admin_dir);
        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load key manager"),
        );

        let challenge = issue_challenge("GX-2024-TX-042-B7C1", std::time::Duration::from_secs(300))
            .expect("issue challenge");
        stores
            .pairings
            .put(record_from_challenge(&challenge, "user-1"))
            .await
            .expect("store challenge");

        let proof = build_pairing_proof(
            &encode_challenge(&challenge).expect("encode challenge"),
            "nodeB",
            "did:guardian:test-node-b",
            &signer.pubkey_der().expect("pubkey"),
            signer,
        )
        .await
        .expect("build proof");

        let paired = authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Api)
            .await
            .expect("authorize api pairing");
        stores
            .devices
            .upsert(PairedDevice {
                device_id: paired.device_id.clone(),
                serial: paired.serial.clone(),
                did: paired.device_did.clone(),
                owner_user_id: paired.owner_user_id.clone(),
                paired_at: "2026-07-01T00:00:00Z".into(),
                reactivated_at: None,
                updated_at: None,
                status: "bootstrap_pending".into(),
                node_id: Some(paired.node_id.clone()),
            })
            .await
            .expect("store pending device");

        stores
            .sync_bootstrap_by_identity(
                None,
                Some(paired.device_id.as_str()),
                None,
                None,
                Some(paired.node_id.as_str()),
            )
            .await
            .expect("sync bootstrap by device id");
        stores
            .sync_bootstrap_by_identity(
                None,
                Some(paired.device_id.as_str()),
                None,
                None,
                Some(paired.node_id.as_str()),
            )
            .await
            .expect("sync bootstrap by device id again");

        let devices: Vec<PairedDevice> = serde_json::from_slice(
            &std::fs::read(admin_dir.join(DEVICES_FILE)).expect("read devices file"),
        )
        .expect("parse devices file");
        let pairings: Vec<PairingChallengeRecord> = serde_json::from_slice(
            &std::fs::read(admin_dir.join(PAIRING_FILE)).expect("read pairings file"),
        )
        .expect("parse pairings file");

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].status, "active");
        assert_eq!(pairings.len(), 1);
        assert!(pairings[0].bootstrap_consumed);
        assert_eq!(
            pairings[0].device_id.as_deref(),
            Some(paired.device_id.as_str())
        );
    }
}
