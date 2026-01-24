use std::cell::UnsafeCell;
use std::ptr::NonNull;

use crate::criu::mount::MountInfoStore;
use crate::criu::namespaces::NsIdStore;
use crate::criu::options::opts;

/// Intrusive list link for sharing groups.
#[derive(Default)]
pub struct SgListLink {
    next: Option<NonNull<SharingGroup>>,
    prev: Option<NonNull<SharingGroup>>,
}

impl SgListLink {
    pub fn new() -> Self {
        Self {
            next: None,
            prev: None,
        }
    }
}

/// Intrusive list head for sharing groups.
#[derive(Default)]
pub struct SgListHead {
    first: Option<NonNull<SharingGroup>>,
}

impl SgListHead {
    pub fn new() -> Self {
        Self { first: None }
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }
}

/// Sharing group for mount-v2.
///
/// Groups mounts that share the same propagation properties.
/// Corresponds to CRIU's `struct sharing_group` from mount-v2.h.
pub struct SharingGroup {
    /// Shared ID identifying this group
    pub shared_id: i32,
    /// Master ID for slave relationships
    pub master_id: i32,

    /// Link for the global sharing_groups list
    pub list_link: SgListLink,

    /// List of mounts in this group (head)
    pub mnt_list: SgListHead,

    /// Children sharing groups (head)
    pub children: SgListHead,
    /// Siblings link
    pub siblings_link: SgListLink,
    /// Parent sharing group
    pub parent: Option<NonNull<SharingGroup>>,

    /// Source string
    pub source: Option<String>,
}

impl SharingGroup {
    pub fn new(shared_id: i32, master_id: i32) -> Self {
        Self {
            shared_id,
            master_id,
            list_link: SgListLink::new(),
            mnt_list: SgListHead::new(),
            children: SgListHead::new(),
            siblings_link: SgListLink::new(),
            parent: None,
            source: None,
        }
    }
}

/// Storage for sharing groups with stable addresses.
pub struct SharingGroupStore {
    groups: Vec<Box<UnsafeCell<SharingGroup>>>,
}

impl Default for SharingGroupStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SharingGroupStore {
    pub fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Gets a raw pointer to a sharing group by index.
    fn get_ptr(&self, idx: usize) -> Option<NonNull<SharingGroup>> {
        self.groups
            .get(idx)
            .map(|cell| NonNull::new(cell.get()).unwrap())
    }

    /// Gets a reference to a sharing group by index.
    pub fn get(&self, idx: usize) -> Option<&SharingGroup> {
        self.groups.get(idx).map(|cell| unsafe { &*cell.get() })
    }

    /// Gets a mutable reference to a sharing group by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut SharingGroup> {
        self.groups.get(idx).map(|cell| unsafe { &mut *cell.get() })
    }

    /// Searches for a sharing group by shared_id and master_id.
    ///
    /// Corresponds to CRIU's `get_sharing_group()`.
    pub fn get_sharing_group(&self, shared_id: i32, master_id: i32) -> Option<usize> {
        self.groups.iter().position(|cell| {
            let sg = unsafe { &*cell.get() };
            sg.shared_id == shared_id && sg.master_id == master_id
        })
    }

    /// Allocates a new sharing group and adds it to the store.
    ///
    /// Corresponds to CRIU's `alloc_sharing_group()`.
    pub fn alloc_sharing_group(&mut self, shared_id: i32, master_id: i32) -> usize {
        let sg = SharingGroup::new(shared_id, master_id);
        let idx = self.groups.len();
        self.groups.push(Box::new(UnsafeCell::new(sg)));

        // Link into the list (in CRIU this adds to global sharing_groups list)
        // Since we use indices, linking is implicit via the store
        if idx > 0 {
            unsafe {
                let new_ptr = self.get_ptr(idx).unwrap();
                let prev_ptr = self.get_ptr(idx - 1).unwrap();

                let new_sg = &mut *new_ptr.as_ptr();
                let prev_sg = &mut *prev_ptr.as_ptr();

                // Simple linked list: prev -> new
                new_sg.list_link.prev = Some(prev_ptr);
                prev_sg.list_link.next = Some(new_ptr);
            }
        }

        idx
    }

    /// Gets or creates a sharing group with the given IDs.
    pub fn get_or_alloc(&mut self, shared_id: i32, master_id: i32) -> usize {
        if let Some(idx) = self.get_sharing_group(shared_id, master_id) {
            idx
        } else {
            self.alloc_sharing_group(shared_id, master_id)
        }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SharingGroup> {
        self.groups.iter().map(|cell| unsafe { &*cell.get() })
    }

    pub fn iter_mut(&self) -> impl Iterator<Item = &mut SharingGroup> {
        self.groups.iter().map(|cell| unsafe { &mut *cell.get() })
    }

    /// Finds a sharing group by shared_id only (for parent lookup).
    pub fn find_by_shared_id(&self, shared_id: i32) -> Option<usize> {
        self.groups.iter().position(|cell| {
            let sg = unsafe { &*cell.get() };
            sg.shared_id == shared_id
        })
    }
}

pub fn resolve_shared_mounts_v2(
    mnt_store: &mut MountInfoStore,
    sg_store: &mut SharingGroupStore,
    ns_store: &NsIdStore,
) -> i32 {
    /*
     * Create sharing groups for each unique shared_id+master_id pair and
     * link each mount to the corresponding sharing group.
     */
    for mi_idx in 0..mnt_store.len() {
        let mi = match mnt_store.get(mi_idx) {
            Some(m) => m,
            None => continue,
        };

        let shared_id = mi.shared_id;
        let master_id = mi.master_id;
        let mnt_id = mi.mnt_id;
        let ns_mountpoint = mi.ns_mountpoint.clone().unwrap_or_default();

        if shared_id == 0 && master_id == 0 {
            continue;
        }

        log::debug!(
            "Inspecting sharing on {:2} shared_id {} master_id {} (@{})",
            mnt_id,
            shared_id,
            master_id,
            ns_mountpoint
        );

        let sg_idx = sg_store.get_or_alloc(shared_id, master_id);

        // Link mount to sharing group
        if let Some(mi) = mnt_store.get_mut(mi_idx) {
            mi.sg = Some(sg_idx);
        }
    }

    /*
     * Collect sharing groups tree. Mount propagation between sharing
     * groups only goes down this tree, meaning that only mounts of same or
     * descendant sharing groups receive mount propagation.
     */
    for sg_idx in 0..sg_store.len() {
        let (master_id, shared_id) = {
            let sg = match sg_store.get(sg_idx) {
                Some(s) => s,
                None => continue,
            };
            (sg.master_id, sg.shared_id)
        };

        if master_id == 0 {
            continue;
        }

        /*
         * Lookup parent sharing group. If one sharing group
         * has master_id equal to shared_id of another sharing
         * group than the former is a child (slave) of the
         * latter. Also sharing groups should not have two
         * parents so we check this here too.
         */
        let mut found_parent: Option<usize> = None;

        for p_idx in 0..sg_store.len() {
            if p_idx == sg_idx {
                continue;
            }

            let p_shared_id = match sg_store.get(p_idx) {
                Some(p) => p.shared_id,
                None => continue,
            };

            if p_shared_id != master_id {
                continue;
            }

            // Check for parent collision
            let sg = sg_store.get(sg_idx).unwrap();
            if sg.parent.is_some() {
                let p = sg_store.get(p_idx).unwrap();
                log::error!(
                    "Sharing group ({}, {}) parent collision ({}, {}) ({:?})",
                    shared_id,
                    master_id,
                    p.shared_id,
                    p.master_id,
                    sg.parent
                );
                return -1;
            }

            let sg = sg_store.get(sg_idx).unwrap();
            if !sg.siblings_link.prev.is_none() || !sg.siblings_link.next.is_none() {
                let p = sg_store.get(p_idx).unwrap();
                log::error!(
                    "External slavery sharing group ({}, {}) has parent ({}, {})",
                    shared_id,
                    master_id,
                    p.shared_id,
                    p.master_id
                );
                return -1;
            }

            found_parent = Some(p_idx);
        }

        // Set parent if found
        if let Some(p_idx) = found_parent {
            let p_ptr = sg_store.get_ptr(p_idx);
            if let (Some(sg), Some(p)) = (sg_store.get_mut(sg_idx), p_ptr) {
                sg.parent = Some(p);
            }
        } else {
            // No parent found - external slavery case
            let sg = sg_store.get(sg_idx).unwrap();
            if sg.parent.is_none() && sg.siblings_link.prev.is_none() && sg.siblings_link.next.is_none() {
                /*
                 * Though we don't have parent sharing group
                 * (inaccessible sharing), we can still have
                 * siblings, sharing groups with same master_id
                 * but different shared_id.
                 */

                // Find first mount in this sharing group to check for external source
                let mut source: Option<String> = None;

                for mi_idx in 0..mnt_store.len() {
                    let mi = match mnt_store.get(mi_idx) {
                        Some(m) => m,
                        None => continue,
                    };

                    if mi.sg != Some(sg_idx) {
                        continue;
                    }

                    // Check for external bind mount or root bind mount
                    if let Some(ext_idx) = mnt_store.mnt_get_external_bind_nodev(mi_idx) {
                        if let Some(ext_mi) = mnt_store.get(ext_idx) {
                            source = ext_mi.external.clone();
                        }
                    } else if mnt_store.mnt_is_root_bind(mi_idx, ns_store) {
                        source = opts().root.clone();
                    }

                    if source.is_some() {
                        break;
                    }
                }

                if source.is_none() {
                    log::error!(
                        "Sharing group ({}, {}) has unreachable sharing. Try --enable-external-masters.",
                        shared_id,
                        master_id
                    );
                    return -1;
                }

                // Set source on this sharing group
                if let Some(sg) = sg_store.get_mut(sg_idx) {
                    sg.source = source.clone();
                }

                log::debug!(
                    "Detected external slavery for shared group ({}, {}) with source {:?}",
                    shared_id,
                    master_id,
                    source
                );
            }
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharing_group_new() {
        let sg = SharingGroup::new(100, 50);
        assert_eq!(sg.shared_id, 100);
        assert_eq!(sg.master_id, 50);
        assert!(sg.mnt_list.is_empty());
        assert!(sg.children.is_empty());
        assert!(sg.parent.is_none());
        assert!(sg.source.is_none());
    }

    #[test]
    fn test_alloc_sharing_group() {
        let mut store = SharingGroupStore::new();
        assert!(store.is_empty());

        let idx = store.alloc_sharing_group(100, 50);
        assert_eq!(idx, 0);
        assert_eq!(store.len(), 1);

        let sg = store.get(idx).unwrap();
        assert_eq!(sg.shared_id, 100);
        assert_eq!(sg.master_id, 50);
    }

    #[test]
    fn test_get_sharing_group_found() {
        let mut store = SharingGroupStore::new();
        store.alloc_sharing_group(100, 50);
        store.alloc_sharing_group(200, 100);
        store.alloc_sharing_group(300, 0);

        let idx = store.get_sharing_group(200, 100);
        assert_eq!(idx, Some(1));

        let sg = store.get(idx.unwrap()).unwrap();
        assert_eq!(sg.shared_id, 200);
        assert_eq!(sg.master_id, 100);
    }

    #[test]
    fn test_get_sharing_group_not_found() {
        let mut store = SharingGroupStore::new();
        store.alloc_sharing_group(100, 50);

        let idx = store.get_sharing_group(999, 888);
        assert!(idx.is_none());
    }

    #[test]
    fn test_get_or_alloc_existing() {
        let mut store = SharingGroupStore::new();
        let idx1 = store.alloc_sharing_group(100, 50);

        let idx2 = store.get_or_alloc(100, 50);
        assert_eq!(idx1, idx2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_get_or_alloc_new() {
        let mut store = SharingGroupStore::new();
        store.alloc_sharing_group(100, 50);

        let idx = store.get_or_alloc(200, 100);
        assert_eq!(idx, 1);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_alloc_multiple() {
        let mut store = SharingGroupStore::new();

        let idx0 = store.alloc_sharing_group(100, 0);
        let idx1 = store.alloc_sharing_group(200, 100);
        let idx2 = store.alloc_sharing_group(300, 100);

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert_eq!(store.len(), 3);

        // Verify linking
        let sg0 = store.get(0).unwrap();
        let sg1 = store.get(1).unwrap();
        let sg2 = store.get(2).unwrap();

        assert!(sg0.list_link.prev.is_none());
        assert!(sg0.list_link.next.is_some());
        assert!(sg1.list_link.prev.is_some());
        assert!(sg1.list_link.next.is_some());
        assert!(sg2.list_link.prev.is_some());
        assert!(sg2.list_link.next.is_none());
    }
}
