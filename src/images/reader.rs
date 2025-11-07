// CRIU image file reader
use prost::Message;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::checkpoint::{CriuCheckpoint, Pagemap};
use crate::error::{CrustError, Result};
use crate::proto::{
    CoreEntry, FdinfoEntry, FileEntry, FsEntry, InventoryEntry, MmEntry, PagemapEntry, PagemapHead,
    PstreeEntry, SeccompEntry, TaskKobjIdsEntry, TimensEntry, TtyInfoEntry,
};

// CRIU image magic: 0x54564319 (not currently validated)

pub struct ImageDir {
    path: PathBuf,
}

impl ImageDir {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_dir() {
            return Err(CrustError::ImageNotFound {
                path: path.display().to_string(),
            });
        }
        Ok(ImageDir { path })
    }

    fn read_image_file(&self, filename: &str) -> Result<Vec<u8>> {
        let img_path = self.path.join(filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // CRIU image format:
        // - 4 bytes: magic number
        // - 4 bytes: image type identifier
        // - 4 bytes: payload size (little-endian u32)
        // - N bytes: protobuf data

        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        // Skip the 12-byte header and return just the protobuf payload
        Ok(buffer[12..].to_vec())
    }

    /// Read inventory.img to get checkpoint metadata
    pub fn read_inventory(&self) -> Result<InventoryEntry> {
        let data = self.read_image_file("inventory.img")?;
        let inventory =
            InventoryEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
                reason: format!("Failed to decode inventory: {}", e),
            })?;
        Ok(inventory)
    }

    /// Read pstree.img to get process tree
    pub fn read_pstree(&self) -> Result<PstreeEntry> {
        let data = self.read_image_file("pstree.img")?;
        let pstree = PstreeEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode pstree: {}", e),
        })?;
        Ok(pstree)
    }

    /// Read core image for a specific PID
    pub fn read_core(&self, pid: u32) -> Result<CoreEntry> {
        let filename = format!("core-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let core = CoreEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode core: {}", e),
        })?;
        Ok(core)
    }

    /// Read memory map for a specific PID
    pub fn read_mm(&self, pid: u32) -> Result<MmEntry> {
        let filename = format!("mm-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let mm = MmEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode mm: {}", e),
        })?;
        Ok(mm)
    }

    /// Read pagemap for a specific PID
    /// Returns PagemapHead and vector of PagemapEntry
    pub fn read_pagemap(&self, pid: u32) -> Result<Pagemap> {
        let filename = format!("pagemap-{}.img", pid);
        let img_path = self.path.join(&filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        // Read the size of PagemapHead from bytes 8-11
        let head_size = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as usize;

        if buffer.len() < 12 + head_size {
            return Err(CrustError::InvalidImage {
                reason: format!("{} truncated (missing PagemapHead)", filename),
            });
        }

        // Decode PagemapHead
        let head_data = &buffer[12..12 + head_size];
        let head = PagemapHead::decode(head_data).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode PagemapHead: {}", e),
        })?;

        // Parse stream of PagemapEntry messages
        // After PagemapHead, entries are stored with 4-byte size prefix (little-endian u32)
        let mut entries = Vec::new();
        let mut pos = 12 + head_size;

        while pos + 4 <= buffer.len() {
            // Read entry size (4 bytes, little-endian)
            let entry_size = u32::from_le_bytes([
                buffer[pos],
                buffer[pos + 1],
                buffer[pos + 2],
                buffer[pos + 3],
            ]) as usize;
            pos += 4;

            if pos + entry_size > buffer.len() {
                break; // Incomplete entry at end of file
            }

            // Decode the entry
            let entry_data = &buffer[pos..pos + entry_size];
            match PagemapEntry::decode(entry_data) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    log::warn!("Failed to decode PagemapEntry at offset {}: {}", pos, e);
                    break;
                }
            }
            pos += entry_size;
        }

        Ok(Pagemap {
            pages_id: head.pages_id,
            entries,
        })
    }

    /// Read pages file containing actual memory data
    pub fn read_pages(&self, pages_id: u32) -> Result<Vec<u8>> {
        let filename = format!("pages-{}.img", pages_id);
        let img_path = self.path.join(&filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Pages file has same 12-byte header
        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        Ok(buffer[12..].to_vec())
    }

    /// Helper: Read entire image file into buffer (with header validation)
    fn read_file_buffer(&self, filename: &str) -> Result<Vec<u8>> {
        let img_path = self.path.join(filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        Ok(buffer)
    }

    /// Helper: Parse CRIU multi-entry format
    /// Format: [4 magic][4 type][4 first_size][first_msg][4 size][msg]...
    /// The header's size field (bytes 8-11) contains the size of the FIRST message
    fn parse_criu_entries<T>(buffer: &[u8], filename: &str) -> Result<Vec<T>>
    where
        T: Message + Default,
    {
        let mut entries = Vec::new();

        // Read first message size from header (bytes 8-11)
        let first_msg_size =
            u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as usize;
        let mut offset = 12;

        // Decode first message
        if offset + first_msg_size <= buffer.len() {
            let msg_data = &buffer[offset..offset + first_msg_size];
            match T::decode(msg_data) {
                Ok(entry) => {
                    entries.push(entry);
                    offset += first_msg_size;
                }
                Err(e) => {
                    log::debug!("Failed to decode first message in {}: {}", filename, e);
                    return Ok(entries);
                }
            }
        } else {
            log::debug!(
                "First message size {} exceeds available data in {}",
                first_msg_size,
                filename
            );
            return Ok(entries);
        }

        // Read remaining messages with [4-byte size][protobuf] format
        while offset + 4 <= buffer.len() {
            let msg_size = u32::from_le_bytes([
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + msg_size > buffer.len() {
                log::debug!(
                    "Incomplete message in {}: expected {} bytes, only {} available",
                    filename,
                    msg_size,
                    buffer.len() - offset
                );
                break;
            }

            let msg_data = &buffer[offset..offset + msg_size];
            match T::decode(msg_data) {
                Ok(entry) => {
                    entries.push(entry);
                }
                Err(e) => {
                    log::debug!(
                        "Failed to decode message at offset {} in {}: {}",
                        offset,
                        filename,
                        e
                    );
                    break;
                }
            }
            offset += msg_size;
        }

        log::info!(
            "Successfully parsed {} messages from {}",
            entries.len(),
            filename
        );
        Ok(entries)
    }

    /// Read files.img containing file table
    pub fn read_files(&self) -> Result<Vec<FileEntry>> {
        let buffer = self.read_file_buffer("files.img")?;
        Self::parse_criu_entries(&buffer, "files.img")
    }

    /// Read fdinfo for a specific FD number
    pub fn read_fdinfo(&self, fd: u32) -> Result<FdinfoEntry> {
        let filename = format!("fdinfo-{}.img", fd);
        let data = self.read_image_file(&filename)?;
        let fdinfo = FdinfoEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode fdinfo: {}", e),
        })?;
        Ok(fdinfo)
    }

    /// Read filesystem context for a specific PID
    pub fn read_fs(&self, pid: u32) -> Result<FsEntry> {
        let filename = format!("fs-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let fs = FsEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode fs: {}", e),
        })?;
        Ok(fs)
    }

    /// Read IDs (namespace info) for a specific PID
    pub fn read_ids(&self, pid: u32) -> Result<TaskKobjIdsEntry> {
        let filename = format!("ids-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let ids = TaskKobjIdsEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode ids: {}", e),
        })?;
        Ok(ids)
    }

    /// Read seccomp filters
    pub fn read_seccomp(&self) -> Result<SeccompEntry> {
        let data = self.read_image_file("seccomp.img")?;
        let seccomp = SeccompEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode seccomp: {}", e),
        })?;
        Ok(seccomp)
    }

    /// Read time namespace info
    pub fn read_timens(&self, id: u32) -> Result<TimensEntry> {
        let filename = format!("timens-{}.img", id);
        let data = self.read_image_file(&filename)?;
        let timens = TimensEntry::decode(&data[..]).map_err(|e| CrustError::InvalidImage {
            reason: format!("Failed to decode timens: {}", e),
        })?;
        Ok(timens)
    }

    /// Read TTY info
    pub fn read_tty_info(&self) -> Result<Vec<TtyInfoEntry>> {
        let buffer = self.read_file_buffer("tty-info.img")?;
        Self::parse_criu_entries(&buffer, "tty-info.img")
    }

    /// Load a complete CRIU checkpoint
    pub fn load_checkpoint(&self) -> Result<CriuCheckpoint> {
        let pstree = self.read_pstree()?;
        let pid = pstree.pid;

        let core = self.read_core(pid)?;
        let mm = self.read_mm(pid)?;
        let pagemap = self.read_pagemap(pid)?;

        let pages_data = self.read_pages(pagemap.pages_id)?;

        // Optional files - don't fail if they don't exist
        let files = self.read_files().ok();
        let fs = self.read_fs(pid).ok();
        let ids = self.read_ids(pid).ok();
        let seccomp = self.read_seccomp().ok();
        let tty_info = self.read_tty_info().ok();

        // Try to read timens with ID 0 (common case)
        let timens = self.read_timens(0).ok();

        Ok(CriuCheckpoint {
            pstree,
            core,
            mm,
            pagemap,
            pages_data,
            files,
            fs,
            ids,
            seccomp,
            timens,
            tty_info,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
