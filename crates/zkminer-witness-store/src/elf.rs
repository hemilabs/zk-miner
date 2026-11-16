//! The shared ELF area (plan §15.1): content-addressed by image id under `<root>/elfs/`, never
//! copied per bundle, refcounted by the versions whose `image_id` names it.

use std::sync::Arc;

use alloy_primitives::B256;

use crate::error::{Defect, Reject, StoreError};
use crate::fsutil::{is_enoent, read_capped, Kind, ReadError};
use crate::layout::{elf_name, parse_b256_name};
use crate::store::{entry_read_error, Inner, State, Store, Usage, MAX_ELF_BYTES};

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
    /// Takes a hold; the caller holds the state lock.
    fn hold_locked(self: &Arc<Self>, st: &mut State, image_id: B256) -> ElfHold {
        *st.elf_holds.entry(image_id).or_default() += 1;
        ElfHold { inner: Arc::clone(self), image_id }
    }

    /// Reads and verifies a retained ELF: `Missing` when absent from an available area.
    pub(crate) fn read_elf(
        &self,
        image_id: &B256,
        image_id_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<Vec<u8>, StoreError> {
        let elfs = self.elfs()?;
        let name = elf_name(image_id);
        let p = elfs.child(&name);
        let bytes = match read_capped(&elfs, &name, MAX_ELF_BYTES) {
            Ok(b) => b,
            Err(ReadError::Io(e)) if is_enoent(&e) => return Err(StoreError::Missing { path: p }),
            Err(e) => return Err(entry_read_error(e, &p)),
        };
        if image_id_fn(&bytes) != Some(*image_id) {
            return Err(StoreError::corrupt(Defect::ImageId, &p));
        }
        Ok(bytes)
    }

    /// Deletes ELFs that no version references and nothing holds. Returns the ones removed.
    pub(crate) fn collect_elfs(&self, st: &mut State, candidates: &[B256]) -> Result<Vec<B256>, StoreError> {
        let mut removed = Vec::new();
        let mut elfs = None;
        for id in candidates {
            if !st.elf_collectable(id) {
                continue;
            }
            let dir = match &elfs {
                Some(d) => d,
                None => elfs.insert(self.elfs()?),
            };
            if self.remove_entry(st, dir, &elf_name(id), false, &mut |_| {})?.is_some() {
                removed.push(*id);
            }
        }
        Ok(removed)
    }

    /// Image ids of every ELF file in the area.
    pub(crate) fn elf_ids(&self) -> Result<Vec<B256>, StoreError> {
        let elfs = self.elfs()?;
        Ok(elfs
            .entries()
            .map_err(|e| StoreError::io(e, elfs.path()))?
            .into_iter()
            .filter_map(|e| e.utf8().and_then(parse_b256_name))
            .collect())
    }
}

impl Store {
    /// Retains an ELF under its image id, verified with `image_id_fn` (risc0's computation, supplied
    /// by the caller), and holds it until the returned [`ElfHold`] is dropped. The hold is taken
    /// before the area is looked at, so a concurrent eviction cannot collect the copy this call
    /// accepts. An existing copy that verifies is kept (stripped and unstripped copies share an
    /// image id); one that does not is replaced. [`crate::BundleWriter::finish`] requires the ELF
    /// to be present.
    pub fn put_elf(
        &self,
        image_id: B256,
        bytes: &[u8],
        image_id_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<ElfHold, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        if bytes.len() as u64 > MAX_ELF_BYTES {
            return Err(StoreError::Rejected(Reject::Record(Defect::TooLarge)));
        }
        if image_id_fn(bytes) != Some(image_id) {
            return Err(StoreError::Rejected(Reject::Record(Defect::ImageId)));
        }
        let hold = {
            let mut st = inner.state();
            inner.hold_locked(&mut st, image_id)
        };
        match inner.read_elf(&image_id, image_id_fn) {
            Ok(_) => return Ok(hold),
            Err(StoreError::Missing { .. } | StoreError::Corrupt { .. }) => {}
            Err(e) => return Err(e),
        }
        let elfs = inner.elfs()?;
        let name = elf_name(&image_id);
        let written = {
            let mut st = inner.state();
            (|| {
                let add = match elfs.stat_opt(&name) {
                    Ok(Some(s)) if s.kind == Kind::File => Usage::new((bytes.len() as u64).saturating_sub(s.len), 0),
                    Ok(Some(_)) => return Err(StoreError::layout(&elfs.child(&name))),
                    Ok(None) => Usage::new(bytes.len() as u64, 1),
                    Err(e) => return Err(StoreError::io(e, &elfs.child(&name))),
                };
                inner.admit(&st, add)?;
                inner.write_atomic(&mut st, &elfs, &name, bytes, 0o444)
            })()
        };
        written.map(|()| hold)
    }

    /// Holds an ELF already in the store; [`StoreError::Missing`] if it is not. Checked and held
    /// under the store lock, so it cannot be collected in between.
    pub fn hold_elf(&self, image_id: B256) -> Result<ElfHold, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let elfs = inner.elfs()?;
        let name = elf_name(&image_id);
        let p = elfs.child(&name);
        let mut st = inner.state();
        match elfs.stat_opt(&name) {
            Ok(Some(s)) if s.kind == Kind::File => Ok(inner.hold_locked(&mut st, image_id)),
            Ok(Some(_)) => Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
            Ok(None) => Err(StoreError::Missing { path: p }),
            Err(e) => Err(StoreError::io(e, &p)),
        }
    }

    /// Reads a retained ELF, re-verifying its image id ([`StoreError::Corrupt`] when it does not
    /// match, [`StoreError::Missing`] when absent).
    pub fn open_elf(&self, image_id: B256, image_id_fn: &dyn Fn(&[u8]) -> Option<B256>) -> Result<Vec<u8>, StoreError> {
        self.inner.check_usable()?;
        self.inner.read_elf(&image_id, image_id_fn)
    }

    /// Readable versions referencing the ELF.
    pub fn elf_refs(&self, image_id: B256) -> u32 {
        self.inner.state().elf_refs.get(&image_id).copied().unwrap_or(0)
    }
}
