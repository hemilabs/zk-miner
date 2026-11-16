//! The shared ELF area (plan §15.1): content-addressed by image id under `<root>/elfs/`, never
//! copied per bundle, refcounted by the versions whose `image_id` names it.

use std::fs;
use std::io;
use std::sync::Arc;

use alloy_primitives::B256;

use crate::error::{Defect, Reject, StoreError};
use crate::fsutil::{read_capped, ReadError};
use crate::layout::elf_name;
use crate::store::{entry_read_error, Inner, Store, Usage, MAX_ELF_BYTES};

/// Keeps an ELF from being collected while a simulation that will reference it is in flight (the
/// task-scoped hold that a bundle's reference replaces once it is published). In memory only.
pub struct ElfHold {
    inner: Arc<Inner>,
    image_id: B256,
}

impl ElfHold {
    pub fn image_id(&self) -> B256 {
        self.image_id
    }
}

impl std::fmt::Debug for ElfHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfHold").field("image_id", &self.image_id).finish()
    }
}

impl Drop for ElfHold {
    fn drop(&mut self) {
        let mut st = self.inner.state();
        if let Some(n) = st.elf_holds.get_mut(&self.image_id) {
            *n -= 1;
            if *n == 0 {
                st.elf_holds.remove(&self.image_id);
            }
        }
    }
}

impl Inner {
    fn hold(self: &Arc<Self>, image_id: B256) -> ElfHold {
        *self.state().elf_holds.entry(image_id).or_default() += 1;
        ElfHold { inner: Arc::clone(self), image_id }
    }

    /// Reads and verifies a retained ELF.
    fn read_elf(&self, image_id: &B256, image_id_fn: &dyn Fn(&[u8]) -> Option<B256>) -> Result<Vec<u8>, StoreError> {
        let p = self.elf_path(image_id);
        let bytes = match read_capped(&p, MAX_ELF_BYTES) {
            Ok(b) => b,
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                let d = self.elfs_dir();
                fs::symlink_metadata(&d).map_err(|e| StoreError::io(e, &d))?;
                return Err(StoreError::Missing { path: p });
            }
            Err(e) => return Err(entry_read_error(e, &p)),
        };
        if image_id_fn(&bytes) != Some(*image_id) {
            return Err(StoreError::corrupt(Defect::ImageId, &p));
        }
        Ok(bytes)
    }

    /// Deletes ELFs that no version references and nothing holds. Returns the ones removed.
    pub(crate) fn collect_elfs(&self, st: &mut crate::store::State, candidates: &[B256]) -> Result<Vec<B256>, StoreError> {
        let mut removed = Vec::new();
        for id in candidates {
            if !st.elf_collectable(id) {
                continue;
            }
            let p = self.elf_path(id);
            match fs::symlink_metadata(&p) {
                Ok(_) => {
                    self.remove_entry(st, &p)?;
                    removed.push(*id);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(StoreError::io(e, &p)),
            }
        }
        Ok(removed)
    }

    /// Image ids of every ELF file in the area.
    pub(crate) fn elf_ids(&self) -> Result<Vec<B256>, StoreError> {
        Ok(crate::store::entries(&self.elfs_dir())?
            .into_iter()
            .filter_map(|(n, _, _)| n.as_deref().and_then(crate::layout::parse_b256_name))
            .collect())
    }
}

impl Store {
    /// Retains an ELF under its image id, verified with `image_id_fn` (risc0's computation, supplied
    /// by the caller), and holds it until the returned [`ElfHold`] is dropped. An existing copy
    /// that verifies is kept (stripped and unstripped copies share an image id); one that does not
    /// is replaced. [`crate::BundleWriter::finish`] requires the ELF to be present.
    pub fn put_elf(
        &self,
        image_id: B256,
        bytes: &[u8],
        image_id_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<ElfHold, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        if bytes.len() as u64 > MAX_ELF_BYTES {
            return Err(StoreError::Rejected(Reject::Record(Defect::TooLarge)));
        }
        if image_id_fn(bytes) != Some(image_id) {
            return Err(StoreError::Rejected(Reject::Record(Defect::ImageId)));
        }
        let existing_ok = match inner.read_elf(&image_id, image_id_fn) {
            Ok(_) => true,
            Err(StoreError::Missing { .. } | StoreError::Corrupt { .. }) => false,
            Err(e) => return Err(e),
        };
        if !existing_ok {
            let mut st = inner.state();
            let p = inner.elf_path(&image_id);
            let old = fs::symlink_metadata(&p).ok().filter(|m| m.is_file()).map(|m| m.len());
            let add = match old {
                Some(o) => Usage::new((bytes.len() as u64).saturating_sub(o), 0),
                None => Usage::new(bytes.len() as u64, 1),
            };
            inner.admit(&st, add)?;
            inner.write_atomic(&mut st, &inner.elfs_dir(), &elf_name(&image_id), bytes, 0o444)?;
        }
        Ok(inner.hold(image_id))
    }

    /// Holds an ELF already in the store; [`StoreError::Missing`] if it is not.
    pub fn hold_elf(&self, image_id: B256) -> Result<ElfHold, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let p = inner.elf_path(&image_id);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() => Ok(inner.hold(image_id)),
            Ok(_) => Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::Missing { path: p }),
            Err(e) => Err(StoreError::io(e, &p)),
        }
    }

    /// Reads a retained ELF, re-verifying its image id ([`StoreError::Corrupt`] when it does not
    /// match, [`StoreError::Missing`] when absent).
    pub fn open_elf(&self, image_id: B256, image_id_fn: &dyn Fn(&[u8]) -> Option<B256>) -> Result<Vec<u8>, StoreError> {
        self.inner.check_root()?;
        self.inner.read_elf(&image_id, image_id_fn)
    }

    /// Readable versions referencing the ELF.
    pub fn elf_refs(&self, image_id: B256) -> u32 {
        self.inner.state().elf_refs.get(&image_id).copied().unwrap_or(0)
    }
}
