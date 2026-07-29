//! ELF binary registry for supported RISC Zero programs.
//!
//! Maps imageId (B256) → ELF binary for known programs.

use alloy_primitives::B256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Registry of known RISC Zero guest programs.
pub struct ElfRegistry {
    /// Map from imageId to ELF binary.
    programs: HashMap<B256, RegisteredProgram>,
    /// Directory to search for ELF files.
    elf_dir: PathBuf,
}

/// A registered guest program.
#[derive(Debug, Clone)]
pub struct RegisteredProgram {
    pub image_id: B256,
    pub name: String,
    pub elf: Vec<u8>,
    /// Expected cycle count (approximate, for estimation).
    pub estimated_cycles: Option<u64>,
}

impl ElfRegistry {
    pub fn new(elf_dir: impl Into<PathBuf>) -> Self {
        Self {
            programs: HashMap::new(),
            elf_dir: elf_dir.into(),
        }
    }

    /// Register a program with its ELF binary.
    pub fn register(&mut self, image_id: B256, name: String, elf: Vec<u8>, estimated_cycles: Option<u64>) {
        self.programs.insert(
            image_id,
            RegisteredProgram {
                image_id,
                name,
                elf,
                estimated_cycles,
            },
        );
    }

    /// Register a program from a file path.
    pub fn register_from_file(
        &mut self,
        image_id: B256,
        name: String,
        path: &Path,
        estimated_cycles: Option<u64>,
    ) -> anyhow::Result<()> {
        let elf = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read ELF from {}: {}", path.display(), e))?;
        self.register(image_id, name, elf, estimated_cycles);
        Ok(())
    }

    /// Load all .elf files from the registry directory.
    pub fn load_from_dir(&mut self) -> anyhow::Result<usize> {
        if !self.elf_dir.exists() {
            std::fs::create_dir_all(&self.elf_dir)?;
            return Ok(0);
        }

        let mut count = 0;
        for entry in std::fs::read_dir(&self.elf_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("elf") {
                let elf = std::fs::read(&path)?;
                // Compute image ID from the ELF (in production, use risc0 compute_image_id)
                let image_id = alloy_primitives::keccak256(&elf);
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                tracing::info!("Loaded ELF: {} (image_id: {})", name, image_id);
                self.register(image_id, name, elf, None);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Look up a program by image ID.
    pub fn get(&self, image_id: &B256) -> Option<&RegisteredProgram> {
        self.programs.get(image_id)
    }

    /// Check if we support a given program.
    pub fn supports(&self, image_id: &B256) -> bool {
        self.programs.contains_key(image_id)
    }

    /// List all registered programs.
    pub fn list(&self) -> Vec<&RegisteredProgram> {
        self.programs.values().collect()
    }

    /// Number of registered programs.
    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }
}
