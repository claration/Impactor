use std::path::{Path, PathBuf};

use idevice::remote_pairing::{PeerDevice, RpPairingFile};
use plist::{Dictionary, Value};

use super::pairing::PairedDevice;
use crate::Error;

#[derive(Debug, Clone)]
pub struct PairingRecord {
    pub udid: String,
    pub name: String,
    pub model: String,
    pub account_id: String,
    pub pairing_file_path: PathBuf,
}

impl std::fmt::Display for PairingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) [{}]", self.name, self.model, self.udid)
    }
}

/// A directory of pairing files.
///
/// Each device gets `<udid>.plist` in the format idevice reads and writes, plus
/// an `<udid>.info.plist` sidecar for the name and model the pairing file
/// doesn't carry.
#[derive(Debug, Clone)]
pub struct PairingStore {
    dir: PathBuf,
}

impl PairingStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    pub fn pairing_file_path(&self, udid: &str) -> Result<PathBuf, Error> {
        Ok(self.dir.join(format!("{}.plist", file_stem(udid)?)))
    }

    fn info_path(&self, udid: &str) -> Result<PathBuf, Error> {
        Ok(self.dir.join(format!("{}.info.plist", file_stem(udid)?)))
    }

    pub async fn save(
        &self,
        device: &PairedDevice,
        pairing_file: &RpPairingFile,
    ) -> Result<PathBuf, Error> {
        let path = self.pairing_file_path(&device.udid)?;
        let info_path = self.info_path(&device.udid)?;

        tokio::fs::create_dir_all(&self.dir).await?;
        tokio::fs::write(&path, pairing_file.to_bytes()).await?;

        let mut info = Dictionary::new();
        info.insert("udid".into(), Value::String(device.udid.clone()));
        info.insert("name".into(), Value::String(device.name.clone()));
        info.insert("model".into(), Value::String(device.model.clone()));
        info.insert(
            "account_id".into(),
            Value::String(device.account_id.clone()),
        );
        info.insert(
            "paired_at".into(),
            Value::Date(std::time::SystemTime::now().into()),
        );

        let mut buf = Vec::new();
        plist::to_writer_xml(&mut buf, &info)?;
        tokio::fs::write(&info_path, buf).await?;

        Ok(path)
    }

    pub async fn load(&self, udid: &str) -> Result<RpPairingFile, Error> {
        let path = self.pairing_file_path(udid)?;
        if !tokio::fs::try_exists(&path).await? {
            return Err(Error::PairingNotFound(udid.to_string()));
        }
        Ok(RpPairingFile::read_from_file(&path).await?)
    }

    pub async fn list(&self) -> Result<Vec<PairingRecord>, Error> {
        let mut records = Vec::new();

        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(e) => return Err(e.into()),
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(udid) = pairing_file_udid(&path) else {
                continue;
            };

            // One bad file shouldn't hide every other paired device.
            match self.record(&udid).await {
                Ok(record) => records.push(record),
                Err(e) => log::warn!("skipping unreadable pairing for {udid}: {e}"),
            }
        }

        records.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.udid.cmp(&b.udid)));
        Ok(records)
    }

    /// Finds the pairing matching an `identifier`/`authTag` from a
    /// `_remotepairing._tcp` TXT record.
    ///
    /// The device advertises the tag without saying whose it is, so every stored
    /// pairing is tested: the tag is a keyed hash of the identifier under that
    /// pairing's `alt_irk`, which only its owner can reproduce.
    pub async fn find(
        &self,
        identifier: &str,
        auth_tag: &str,
    ) -> Result<Option<PairingRecord>, Error> {
        for record in self.list().await? {
            let pairing_file = match self.load(&record.udid).await {
                Ok(file) => file,
                Err(e) => {
                    log::warn!("skipping unreadable pairing for {}: {e}", record.udid);
                    continue;
                }
            };

            let Some(alt_irk) = pairing_file.alt_irk() else {
                continue;
            };

            if PeerDevice::validate_auth_tag(alt_irk, identifier, auth_tag) {
                return Ok(Some(record));
            }
        }

        Ok(None)
    }

    pub async fn remove(&self, udid: &str) -> Result<bool, Error> {
        let removed = remove_if_present(&self.pairing_file_path(udid)?).await?;
        remove_if_present(&self.info_path(udid)?).await?;
        Ok(removed)
    }

    async fn record(&self, udid: &str) -> Result<PairingRecord, Error> {
        let pairing_file_path = self.pairing_file_path(udid)?;
        let info = self.read_info(udid).await?;

        let field = |key: &str| {
            info.as_ref()
                .and_then(|info| info.get(key))
                .and_then(Value::as_string)
                .map(str::to_string)
        };

        Ok(PairingRecord {
            // A pairing file alone is still usable, so missing metadata falls back.
            name: field("name").unwrap_or_else(|| udid.to_string()),
            model: field("model").unwrap_or_else(|| "Unknown".to_string()),
            account_id: field("account_id").unwrap_or_default(),
            udid: udid.to_string(),
            pairing_file_path,
        })
    }

    async fn read_info(&self, udid: &str) -> Result<Option<Dictionary>, Error> {
        let path = self.info_path(udid)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(plist::from_bytes::<Dictionary>(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

async fn remove_if_present(path: &Path) -> Result<bool, Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn pairing_file_udid(path: &Path) -> Option<String> {
    if path.extension()?.to_str()? != "plist" {
        return None;
    }

    let stem = path.file_stem()?.to_str()?;
    if stem.ends_with(".info") {
        return None;
    }

    Some(stem.to_string())
}

/// The UDID comes from the device, so reject anything that would escape the
/// store directory before using it as a file name.
fn file_stem(udid: &str) -> Result<&str, Error> {
    let valid = !udid.is_empty()
        && udid.len() <= 128
        && udid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));

    if valid {
        Ok(udid)
    } else {
        Err(Error::PairingInvalidUdid(udid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared with idevice's own validate_auth_tag test.
    const ALT_IRK: [u8; 16] = [
        0x32, 0x0a, 0x7a, 0x64, 0x63, 0xf3, 0x5c, 0xcd, 0xa4, 0xbb, 0xd6, 0xeb, 0xe3, 0xab, 0xec,
        0x8b,
    ];
    const IDENTIFIER: &str = "2BE6E510-0325-4365-923E-B14C6F57DB3A";
    const AUTH_TAG: &str = "kXjlTr2l";

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn temp_store() -> PairingStore {
        let dir = std::env::temp_dir().join(format!("plume-pairing-test-{}", uuid::Uuid::new_v4()));
        PairingStore::new(dir)
    }

    fn sample_device() -> PairedDevice {
        PairedDevice {
            udid: "00008110-001A2B3C00000000".to_string(),
            name: "Living Room".to_string(),
            model: "AppleTV11,1".to_string(),
            account_id: "plume".to_string(),
        }
    }

    #[test]
    fn find_matches_a_saved_pairing_by_auth_tag() {
        let store = temp_store();
        let device = sample_device();

        let mut pairing_file = RpPairingFile::generate("plume");
        pairing_file.alt_irk = Some(ALT_IRK.to_vec());

        block_on(async {
            store.save(&device, &pairing_file).await.unwrap();

            let found = store.find(IDENTIFIER, AUTH_TAG).await.unwrap();
            let found = found.expect("saved pairing should match its own auth tag");
            assert_eq!(found.udid, device.udid);
            assert_eq!(found.name, "Living Room");
            assert_eq!(found.model, "AppleTV11,1");

            assert!(store.find(IDENTIFIER, "AAAAAAAA").await.unwrap().is_none());
            assert!(
                store
                    .find("not-our-identifier", AUTH_TAG)
                    .await
                    .unwrap()
                    .is_none()
            );

            assert!(store.remove(&device.udid).await.unwrap());
            assert!(store.find(IDENTIFIER, AUTH_TAG).await.unwrap().is_none());

            tokio::fs::remove_dir_all(store.directory()).await.ok();
        });
    }

    #[test]
    fn list_is_empty_when_nothing_has_been_paired() {
        let store = temp_store();
        assert!(block_on(store.list()).unwrap().is_empty());
    }

    #[test]
    fn file_stem_rejects_path_traversal() {
        assert!(file_stem("../../etc/passwd").is_err());
        assert!(file_stem("a/b").is_err());
        assert!(file_stem("a.b").is_err());
        assert!(file_stem("").is_err());
    }

    #[test]
    fn file_stem_accepts_a_real_udid() {
        assert!(file_stem("00008110-001A2B3C00000000").is_ok());
    }

    #[test]
    fn pairing_file_udid_ignores_sidecars() {
        assert_eq!(
            pairing_file_udid(Path::new("/x/00008110-001A.plist")),
            Some("00008110-001A".to_string())
        );
        assert_eq!(
            pairing_file_udid(Path::new("/x/00008110-001A.info.plist")),
            None
        );
        assert_eq!(pairing_file_udid(Path::new("/x/notes.txt")), None);
    }
}
