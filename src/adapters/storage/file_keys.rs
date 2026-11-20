//! Keys in a directory, sealed under a wrapping key (agc_core.h
//! `key_store_uri = "file:<directory>"`).
//!
//! - One file per key, `<key id>.key`: a sealed record of the whole Key
//!   aggregate. A write replaces the file atomically (write a temporary
//!   file, sync it, rename it over the old one, sync the directory), so a
//!   crash leaves either the old record or the new one, never a torn one.
//! - Every record is AES-256-GCM sealed under the wrapping key, with the key
//!   id as associated data: a record copied over another key's file, or
//!   edited, fails to open. The nonce is fresh per write.
//! - The directory is locked for the store's lifetime (`.lock`, an exclusive
//!   advisory lock): a second store on it, in this process or another,
//!   fails rather than shares it.
//! - All keys are loaded and opened when the store opens, so a damaged
//!   store fails at agc_ctx_open, not at some later operation, and lookups
//!   are served from memory under the same lock discipline as the in-memory
//!   repository.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use prost::Message;
use zeroize::Zeroizing;

use crate::domain::core::{Code, Error, ScopeSpecification, poisoned};
use crate::domain::key::*;
use crate::proto::api;
use crate::secret::{Locking, SecretBytes, extend_secret};

const FORMAT_V1: u8 = 1;
const NONCE_LEN: usize = 12;
const EXTENSION: &str = "key";

/// A wrapping key: 32 bytes in memory for secrets (locked, kept out of core
/// dumps on Linux, zeroed when dropped), like the key material it guards.
pub struct WrappingKey(SecretBytes);

impl WrappingKey {
    /// Reads the key from `path`: exactly 32 bytes, in a regular file that
    /// neither the group nor others can read (Unix), so the key that guards
    /// every stored key is not itself left readable.
    /// With `Locking::Required` it fails (`ResourceExhausted`) if the key
    /// cannot be locked in RAM.
    pub fn from_file(path: &Path, locking: Locking) -> Result<WrappingKey, Error> {
        const OP: &str = "WrappingKey::from_file";
        let invalid = |m: String| Error::new(Code::InvalidArgument, OP, format!("{}: {m}", path.display()));
        let meta = fs::metadata(path).map_err(|e| invalid(format!("cannot read the wrapping key: {e}")))?;
        if !meta.is_file() {
            return Err(invalid("the wrapping key is not a regular file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(invalid("the wrapping key is readable by group or others; restrict it to 0600".into()));
            }
        }
        let bytes = Zeroizing::new(fs::read(path).map_err(|e| invalid(format!("cannot read the wrapping key: {e}")))?);
        if bytes.len() != 32 {
            return Err(invalid(format!("the wrapping key must be 32 bytes, not {}", bytes.len())));
        }
        let key = SecretBytes::new_with(&bytes, locking).map_err(|_| {
            Error::new(
                Code::ResourceExhausted,
                OP,
                "the wrapping key cannot be locked in RAM (RLIMIT_MEMLOCK is used up), and locked memory is required",
            )
        })?;
        Ok(WrappingKey(key))
    }

    #[cfg(test)]
    pub fn from_bytes(key: [u8; 32]) -> WrappingKey {
        WrappingKey(SecretBytes::new_with(&key, Locking::BestEffort).unwrap())
    }

    fn cipher(&self) -> aes_gcm::Aes256Gcm {
        aes_gcm::Aes256Gcm::new_from_slice(&self.0).expect("a wrapping key is 32 bytes")
    }
}

pub struct FileKeyRepository {
    dir: PathBuf,
    key: WrappingKey,
    state: RwLock<State>,
    /// Held for the store's lifetime: the directory lock. `None` once a
    /// forked child has let go of its inherited copy (see
    /// `release_inherited_lock`).
    lock: Mutex<Option<File>>,
}

#[derive(Default)]
struct State {
    keys: HashMap<KeyId, Key>,
    names: HashMap<String, KeyId>,
}

fn io(op: &'static str, what: &str, e: std::io::Error) -> Error {
    Error::new(Code::Internal, op, format!("key store: {what}: {e}"))
}

impl FileKeyRepository {
    /// Opens (creating if needed) the store in `dir`, locks it and loads
    /// every key. A record that does not open under `key`, or that breaks
    /// the Key aggregate's invariants, fails the whole open.
    /// The loaded key material is locked as `locking` asks; with
    /// `Locking::Required` a key that cannot be locked fails the open.
    pub fn open(dir: &Path, key: WrappingKey, locking: Locking) -> Result<FileKeyRepository, Error> {
        const OP: &str = "FileKeyRepository::open";
        private_dir().create(dir).map_err(|e| io(OP, "cannot create the directory", e))?;
        let lock = private_file()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(".lock"))
            .map_err(|e| io(OP, "cannot create the lock file", e))?;
        lock.try_lock().map_err(|_| {
            Error::new(Code::ConcurrentAccess, OP, format!("key store {} is in use by another context", dir.display()))
        })?;
        let mut state = State::default();
        for entry in fs::read_dir(dir).map_err(|e| io(OP, "cannot list the directory", e))? {
            let path = entry.map_err(|e| io(OP, "cannot list the directory", e))?.path();
            if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
                continue;
            }
            let id = path.file_stem().and_then(|s| s.to_str()).map(KeyId::new).ok_or_else(|| {
                Error::new(Code::Internal, OP, format!("key store: unexpected file {}", path.display()))
            })?;
            let sealed = fs::read(&path).map_err(|e| io(OP, "cannot read a key", e))?;
            let k = decode(&open_record(&key, &id, &sealed)?, locking)?;
            if k.id() != &id {
                return Err(Error::new(Code::Internal, OP, format!("key store: {} holds another key", path.display())));
            }
            if state.names.insert(k.name().to_owned(), id.clone()).is_some() {
                return Err(Error::new(Code::Internal, OP, format!("key store: two keys are named {}", k.name())));
            }
            state.keys.insert(id, k);
        }
        Ok(FileKeyRepository { dir: dir.to_owned(), key, state: RwLock::new(state), lock: Mutex::new(Some(lock)) })
    }

    /// In a forked child: closes the child's copy of the lock descriptor,
    /// so that a fresh store can lock the directory once the parent has let
    /// go of it. The lock belongs to the open file description that parent
    /// and child share, so this only closes; it never unlocks, which would
    /// release the parent's lock too. The store is unusable afterwards; only
    /// a poisoned context, about to be replaced, calls this.
    pub fn release_inherited_lock(&self) {
        // A poisoned mutex still hands out the file: the child closes it either way.
        drop(self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take());
    }

    fn path(&self, id: &KeyId) -> PathBuf {
        self.dir.join(format!("{}.{EXTENSION}", id.as_str()))
    }

    /// Writes `k`'s record atomically: temporary file, sync, rename, sync
    /// the directory.
    fn write(&self, k: &Key) -> Result<(), Error> {
        const OP: &str = "FileKeyRepository::write";
        let sealed = seal_record(&self.key, k.id(), &encode(k))?;
        let target = self.path(k.id());
        let tmp = self.dir.join(format!(".{}.tmp", k.id().as_str()));
        let mut f = private_file()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| io(OP, "cannot write a key", e))?;
        f.write_all(&sealed).and_then(|()| f.sync_all()).map_err(|e| io(OP, "cannot write a key", e))?;
        drop(f);
        fs::rename(&tmp, &target).map_err(|e| io(OP, "cannot replace a key", e))?;
        sync_dir(&self.dir).map_err(|e| io(OP, "cannot sync the directory", e))
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "G30: reachable once Go implements DeleteKey"))]
    fn remove(&self, id: &KeyId) -> Result<(), Error> {
        const OP: &str = "FileKeyRepository::remove";
        fs::remove_file(self.path(id)).map_err(|e| io(OP, "cannot delete a key", e))?;
        sync_dir(&self.dir).map_err(|e| io(OP, "cannot sync the directory", e))
    }
}

/// Makes a rename or removal in `dir` durable.
/// Creates directories readable by their owner only (0700 on Unix): the
/// records are sealed, but their names, number and sizes are not.
fn private_dir() -> fs::DirBuilder {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b
}

/// Opens files created as readable by their owner only (0600 on Unix).
fn private_file() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    // Miri cannot fsync a directory handle; everything else about a write
    // still runs under it.
    #[cfg(miri)]
    {
        let _ = dir;
        Ok(())
    }
    #[cfg(not(miri))]
    File::open(dir)?.sync_all()
}

impl KeyRepository for FileKeyRepository {
    fn create(&self, mut k: Key) -> Result<Key, Error> {
        const OP: &str = "FileKeyRepository.create";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        if s.keys.contains_key(k.id()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key id {} exists", k.id().as_str())));
        }
        if s.names.contains_key(k.name()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key name {} exists", k.name())));
        }
        k.set_revision(1);
        // The file first: if it cannot be written, nothing is recorded.
        self.write(&k)?;
        s.names.insert(k.name().into(), k.id().clone());
        s.keys.insert(k.id().clone(), k.clone());
        Ok(k)
    }

    fn update(&self, mut k: Key) -> Result<Key, Error> {
        const OP: &str = "FileKeyRepository.update";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        let stored = s
            .keys
            .get(k.id())
            .ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("no key with id {}", k.id().as_str())))?;
        if stored.revision() != k.revision() {
            return Err(Error::new(Code::ConcurrentAccess, OP, format!("key {} changed since it was read; retry", k.name())));
        }
        k.set_revision(k.revision() + 1);
        self.write(&k)?;
        s.keys.insert(k.id().clone(), k.clone());
        Ok(k)
    }

    fn get_by_id(&self, id: &KeyId) -> Result<Option<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("FileKeyRepository.get_by_id"))?;
        Ok(s.keys.get(id).cloned())
    }

    fn get_by_name(&self, name: &str) -> Result<Option<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("FileKeyRepository.get_by_name"))?;
        Ok(s.names.get(name).and_then(|id| s.keys.get(id)).cloned())
    }

    fn delete(&self, id: &KeyId) -> Result<(), Error> {
        const OP: &str = "FileKeyRepository.delete";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        let k = s.keys.get(id).ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("no key with id {}", id.as_str())))?;
        let name = k.name().to_owned();
        self.remove(id)?;
        s.keys.remove(id);
        s.names.remove(&name);
        Ok(())
    }

    fn list(&self) -> Result<Vec<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("FileKeyRepository.list"))?;
        let mut keys: Vec<Key> = s.keys.values().cloned().collect();
        keys.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(keys)
    }
}

// --- Sealing ----------------------------------------------------------------

/// `nonce (12) | AES-256-GCM(record)`, the key id as associated data.
fn seal_record(key: &WrappingKey, id: &KeyId, record: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|e| Error::new(Code::InsufficientEntropy, "seal_record", format!("the OS random generator failed: {e}")))?;
    let sealed = key
        .cipher()
        .encrypt(nonce.as_slice().try_into().expect("12-byte nonce"), Payload { msg: record, aad: id.as_str().as_bytes() })
        .map_err(|_| Error::new(Code::Internal, "seal_record", "sealing a key record failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_record(key: &WrappingKey, id: &KeyId, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    const OP: &str = "open_record";
    let bad = || {
        Error::new(
            Code::Internal,
            OP,
            format!("key store: the record of {} does not open: wrong wrapping key, or the record is damaged", id.as_str()),
        )
    };
    if sealed.len() < NONCE_LEN {
        return Err(bad());
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    key.cipher()
        .decrypt(nonce.try_into().expect("split at NONCE_LEN"), Payload { msg: ct, aad: id.as_str().as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| bad())
}

// --- The record -------------------------------------------------------------
//
// `1 | key | versions`, where every field is length-prefixed (u32 BE) or a
// fixed-width integer (BE), and a version's scope specification is the API
// message in protobuf. Times are seconds and nanoseconds since 1970.

fn encode(k: &Key) -> Zeroizing<Vec<u8>> {
    let mut w = Writer(Zeroizing::new(Vec::new()));
    w.push(FORMAT_V1);
    w.str(k.id().as_str());
    w.str(k.name());
    w.str(k.policy());
    w.u32(k.state() as i32 as u32);
    w.time(k.created_at());
    w.time(k.updated_at());
    w.u64(k.revision());
    w.u32(u32::try_from(k.versions().len()).expect("far fewer than 2^32 versions"));
    for v in k.versions() {
        w.u32(v.number());
        w.str(v.template_id());
        w.str(v.provider());
        w.bytes(&v.scope_spec().to_proto().encode_to_vec());
        w.bytes(v.material());
        let p = v.provenance();
        w.push(u8::from(p.extractable));
        w.push(u8::from(p.approved_lineage));
        match &p.origin {
            Origin::Generated => w.push(1),
            Origin::Imported => w.push(2),
            Origin::Retained { source_version } => {
                w.push(3);
                w.u32(*source_version);
            }
            Origin::Transferred { source_version, source_provider } => {
                w.push(4);
                w.u32(*source_version);
                w.str(source_provider);
            }
        }
        w.time(v.created_at());
    }
    w.0
}

fn decode(b: &[u8], locking: Locking) -> Result<Key, Error> {
    let mut r = Reader(b);
    if r.u8()? != FORMAT_V1 {
        return Err(malformed());
    }
    let id = KeyId::new(r.str()?);
    let name = r.str()?;
    let policy = r.str()?;
    let state = i32::try_from(r.u32()?).ok().and_then(|s| api::KeyLifecycleState::try_from(s).ok()).ok_or_else(malformed)?;
    let created_at = r.time()?;
    let updated_at = r.time()?;
    let revision = r.u64()?;
    let n = r.u32()?;
    let mut versions = Vec::with_capacity(n.min(1024) as usize);
    for _ in 0..n {
        let number = r.u32()?;
        let template_id = r.str()?;
        let provider = r.str()?;
        let scope = api::ScopeSpecification::decode(r.bytes()?).map_err(|_| malformed())?;
        let scope_spec = ScopeSpecification::from_proto(&scope).map_err(|_| malformed())?;
        let material = Zeroizing::new(r.bytes()?.to_vec());
        let extractable = r.bool()?;
        let approved_lineage = r.bool()?;
        let origin = match r.u8()? {
            1 => Origin::Generated,
            2 => Origin::Imported,
            3 => Origin::Retained { source_version: r.u32()? },
            4 => Origin::Transferred { source_version: r.u32()?, source_provider: r.str()? },
            _ => return Err(malformed()),
        };
        let created = r.time()?;
        versions.push(Version::new(
            number,
            template_id,
            provider,
            scope_spec,
            material,
            Provenance { extractable, approved_lineage, origin },
            created,
            locking,
        )?);
    }
    if !r.0.is_empty() {
        return Err(malformed());
    }
    Key::restore(id, &name, &policy, state, versions, created_at, updated_at, revision)
}

fn malformed() -> Error {
    Error::new(Code::Internal, "FileKeyRepository", "key store: a key record is malformed")
}

/// The record encoder. A record holds key material, so every write goes
/// through `extend_secret`: growing the buffer must not hand an earlier one,
/// with material in it, back to the allocator unwiped.
struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    fn push(&mut self, b: u8) {
        extend_secret(&mut self.0, &[b]);
    }
    fn u32(&mut self, v: u32) {
        extend_secret(&mut self.0, &v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        extend_secret(&mut self.0, &v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).expect("records are far below 4 GiB"));
        extend_secret(&mut self.0, b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn time(&mut self, t: SystemTime) {
        // Times come from the system clock, after 1970.
        let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
        self.u64(d.as_secs());
        self.u32(d.subsec_nanos());
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(malformed());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed()),
        }
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| malformed())
    }
    fn time(&mut self) -> Result<SystemTime, Error> {
        let secs = self.u64()?;
        let nanos = self.u32()?;
        if nanos >= 1_000_000_000 {
            return Err(malformed());
        }
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(secs, nanos)).ok_or_else(malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::core::Scope;
    use crate::domain::key::testing::{key, version};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("agc-filestore-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn wk() -> WrappingKey {
        WrappingKey::from_bytes([7; 32])
    }

    #[test]
    fn keys_survive_reopening() {
        let d = dir("reopen");
        {
            let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
            let mut k = r.create(key("key_1", "alpha")).unwrap();
            k.add_version(version(2)).unwrap();
            k.transition(api::KeyLifecycleState::Suspended, SystemTime::now()).unwrap();
            r.update(k).unwrap();
            r.create(key("key_2", "beta")).unwrap();
        }
        let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
        let k = r.get_by_name("alpha").unwrap().unwrap();
        assert_eq!((k.versions().len(), k.state(), k.revision()), (2, api::KeyLifecycleState::Suspended, 2));
        assert_eq!(k.current().material(), version(2).material(), "material round-trips");
        assert_eq!(r.list().unwrap().iter().map(Key::name).collect::<Vec<_>>(), ["alpha", "beta"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn records_are_sealed_and_bound_to_their_key() {
        let d = dir("sealed");
        {
            let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
            r.create(key("key_1", "alpha")).unwrap();
            r.create(key("key_2", "beta")).unwrap();
        }
        let raw = fs::read(d.join("key_1.key")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"alpha"), "no plaintext on disk");
        // The wrong wrapping key opens nothing.
        assert_eq!(
            FileKeyRepository::open(&d, WrappingKey::from_bytes([8; 32]), Locking::BestEffort).err().unwrap().code(),
            Code::Internal
        );
        // A record moved over another key's file does not open as that key.
        // read + write rather than fs::copy, which Miri cannot run on macOS (fclonefileat).
        fs::write(d.join("key_2.key"), fs::read(d.join("key_1.key")).unwrap()).unwrap();
        assert_eq!(FileKeyRepository::open(&d, wk(), Locking::BestEffort).err().unwrap().code(), Code::Internal);
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_store_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("private").join("nested");
        let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
        r.create(key("key_1", "one")).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&d.join(".lock")), 0o600);
        assert_eq!(mode(&d.join("key_1.key")), 0o600);
    }

    #[test]
    fn a_store_is_used_by_one_context_at_a_time() {
        let d = dir("lock");
        let first = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
        assert_eq!(
            FileKeyRepository::open(&d, wk(), Locking::BestEffort).err().unwrap().code(),
            Code::ConcurrentAccess
        );
        drop(first);
        assert!(FileKeyRepository::open(&d, wk(), Locking::BestEffort).is_ok(), "released when the first closes");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn update_is_optimistic_and_delete_removes_the_file() {
        let d = dir("cas");
        let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
        let k = r.create(key("key_1", "alpha")).unwrap();
        r.update(k.clone()).unwrap();
        assert_eq!(r.update(k).err().unwrap().code(), Code::ConcurrentAccess, "stale revision");
        r.delete(&KeyId::new("key_1")).unwrap();
        assert!(!d.join("key_1.key").exists());
        assert!(r.get_by_name("alpha").unwrap().is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn every_scope_and_origin_round_trips() {
        for (i, scope) in Scope::ALL.iter().enumerate() {
            let first = Version::new(
                1,
                "t".into(),
                "p".into(),
                ScopeSpecification::any_of(*scope),
                Zeroizing::new(vec![i as u8; 4]),
                Provenance { extractable: i % 2 == 0, approved_lineage: true, origin: Origin::Generated },
                SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123),
                Locking::BestEffort,
            )
            .unwrap();
            let mut k = Key::new(KeyId::new(format!("key_{i}")), "n", "pol", first).unwrap();
            let next = Version::new(
                2,
                "t".into(),
                "q".into(),
                ScopeSpecification::any_of(*scope),
                Zeroizing::new(vec![9; 4]),
                Provenance {
                    extractable: false,
                    approved_lineage: false,
                    origin: Origin::Transferred { source_version: 1, source_provider: "p".into() },
                },
                SystemTime::UNIX_EPOCH + Duration::new(1_700_000_001, 0),
                Locking::BestEffort,
            )
            .unwrap();
            k.add_version(next).unwrap();
            let back = decode(&encode(&k), Locking::BestEffort).unwrap();
            assert_eq!(encode(&back), encode(&k), "{scope:?}");
        }
    }

    #[test]
    fn malformed_records_are_refused() {
        let good = encode(&key("key_1", "alpha"));
        let mut trailing = good.to_vec();
        trailing.push(0);
        for bad in [&[][..], &[2][..], &good[..good.len() - 1], &trailing] {
            assert_eq!(decode(bad, Locking::BestEffort).err().unwrap().code(), Code::Internal, "{} bytes", bad.len());
        }
    }

    #[test]
    #[cfg(unix)]
    fn the_wrapping_key_file_must_be_32_private_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("wkfile");
        fs::create_dir_all(&d).unwrap();
        let p = d.join("wk");
        fs::write(&p, [1u8; 32]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let code = |p: &Path| WrappingKey::from_file(p, Locking::BestEffort).err().unwrap().code();
        assert_eq!(code(&p), Code::InvalidArgument, "world-readable");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(WrappingKey::from_file(&p, Locking::BestEffort).is_ok());
        fs::write(&p, [1u8; 16]).unwrap();
        assert_eq!(code(&p), Code::InvalidArgument, "wrong length");
        assert_eq!(code(&d.join("none")), Code::InvalidArgument);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    #[cfg_attr(miri, ignore = "the leak check uses its own global allocator, not under Miri")]
    fn writing_and_reading_records_leaves_no_copy_of_the_material_behind() {
        #[cfg(not(miri))]
        {
            use crate::secret::leak_check::{CANARY, leaks_during};
            let d = dir("leaks");
            // Long material, so the record's buffer must grow after the first
            // version's material is in it, whatever the growth steps are.
            let material = |n: u32| {
                let mut m = Zeroizing::new(Vec::with_capacity(CANARY.len() + 4096));
                m.extend_from_slice(&CANARY);
                m.resize(CANARY.len() + 4096, 0);
                Version::new(
                    n,
                    "aes-256-gcm-128-96".into(),
                    "fake".into(),
                    ScopeSpecification::any_of(Scope::Aead(api::AeadScope::Standard)),
                    m,
                    Provenance { extractable: true, approved_lineage: false, origin: Origin::Generated },
                    SystemTime::UNIX_EPOCH,
                    Locking::BestEffort,
                )
                .unwrap()
            };
            let leaks = leaks_during(|| {
                // Two versions: the record outgrew its buffer after the first
                // version's material was written.
                let mut k = Key::new(KeyId::new("key_leak"), "leak", "p", material(1)).unwrap();
                k.add_version(material(2)).unwrap();
                {
                    let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
                    r.create(k).unwrap();
                }
                let r = FileKeyRepository::open(&d, wk(), Locking::BestEffort).unwrap();
                let back = r.get_by_name("leak").unwrap().unwrap();
                assert_eq!(&back.current().material()[..CANARY.len()], &CANARY[..]);
            });
            let _ = fs::remove_dir_all(&d);
            assert_eq!(leaks, 0);
        }
    }
}
