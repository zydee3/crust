//! Intrusive doubly-linked list for shared memory.
//!
//! This is a 1:1 port of CRIU's include/common/list.h.
//! Uses raw pointers because these lists exist in MAP_SHARED memory
//! and must work across fork boundaries.

use std::ptr;

/// Intrusive list head - embedded directly in data structures.
/// Maps to: struct list_head (include/common/list.h:15-17)
#[repr(C)]
pub struct ListHead {
    pub prev: *mut ListHead,
    pub next: *mut ListHead,
}

impl ListHead {
    /// Create an uninitialized list head.
    /// MUST call init() before use.
    pub const fn uninit() -> Self {
        Self {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }

    /// Initialize a list head to point to itself (empty list).
    /// Maps to: INIT_LIST_HEAD
    #[inline]
    pub fn init(&mut self) {
        self.next = self as *mut ListHead;
        self.prev = self as *mut ListHead;
    }

    /// Check if list is empty.
    /// Maps to: list_empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.next == self as *const ListHead as *mut ListHead
    }

    /// Add new entry after head.
    /// Maps to: list_add
    #[inline]
    pub unsafe fn add(&mut self, new: *mut ListHead) {
        Self::__add(new, self as *mut ListHead, self.next);
    }

    /// Add new entry before head (at tail).
    /// Maps to: list_add_tail
    #[inline]
    pub unsafe fn add_tail(&mut self, new: *mut ListHead) {
        Self::__add(new, self.prev, self as *mut ListHead);
    }

    /// Delete entry from list.
    /// Maps to: list_del
    #[inline]
    pub unsafe fn del(entry: *mut ListHead) {
        Self::__del((*entry).prev, (*entry).next);
        (*entry).next = POISON1 as *mut ListHead;
        (*entry).prev = POISON2 as *mut ListHead;
    }

    /// Delete entry and reinitialize it.
    /// Maps to: list_del_init
    #[inline]
    pub unsafe fn del_init(entry: *mut ListHead) {
        Self::__del((*entry).prev, (*entry).next);
        (*entry).init();
    }

    /// Move entry from one list to another (at head).
    /// Maps to: list_move
    #[inline]
    pub unsafe fn move_to(&mut self, entry: *mut ListHead) {
        Self::__del((*entry).prev, (*entry).next);
        self.add(entry);
    }

    /// Move entry from one list to another (at tail).
    /// Maps to: list_move_tail
    #[inline]
    pub unsafe fn move_tail(&mut self, entry: *mut ListHead) {
        Self::__del((*entry).prev, (*entry).next);
        self.add_tail(entry);
    }

    /// Check if this is the last entry.
    /// Maps to: list_is_last
    #[inline]
    pub fn is_last(&self, head: *const ListHead) -> bool {
        self.next == head as *mut ListHead
    }

    /// Check if this is the first entry.
    /// Maps to: list_is_first
    #[inline]
    pub fn is_first(&self, head: *const ListHead) -> bool {
        self.prev == head as *mut ListHead
    }

    /// Check if list has exactly one entry.
    /// Maps to: list_is_singular
    #[inline]
    pub fn is_singular(&self) -> bool {
        !self.is_empty() && self.next == self.prev
    }

    /// Internal: add between prev and next.
    #[inline]
    unsafe fn __add(new: *mut ListHead, prev: *mut ListHead, next: *mut ListHead) {
        (*next).prev = new;
        (*new).next = next;
        (*new).prev = prev;
        (*prev).next = new;
    }

    /// Internal: delete by updating prev/next pointers.
    #[inline]
    unsafe fn __del(prev: *mut ListHead, next: *mut ListHead) {
        (*next).prev = prev;
        (*prev).next = next;
    }
}

impl Default for ListHead {
    fn default() -> Self {
        Self::uninit()
    }
}

// Poison values for deleted entries (helps catch use-after-delete)
const POISON1: usize = 0x00100100;
const POISON2: usize = 0x00200200;

/// Get containing struct from list_head pointer.
/// Maps to: list_entry / container_of
///
/// # Safety
/// - `ptr` must be a valid pointer to a ListHead
/// - The ListHead must be embedded in a struct of type T at offset `offset`
#[inline]
pub unsafe fn list_entry<T>(ptr: *mut ListHead, offset: usize) -> *mut T {
    (ptr as *mut u8).sub(offset) as *mut T
}

/// Calculate offset of a field in a struct.
/// Use with list_entry to get containing struct.
#[macro_export]
macro_rules! offset_of {
    ($ty:ty, $field:ident) => {{
        let uninit = std::mem::MaybeUninit::<$ty>::uninit();
        let base = uninit.as_ptr();
        let field = std::ptr::addr_of!((*base).$field);
        (field as usize) - (base as usize)
    }};
}

/// Iterate over list entries.
/// Maps to: list_for_each_entry
#[macro_export]
macro_rules! list_for_each_entry {
    ($pos:ident, $head:expr, $ty:ty, $member:ident, $body:block) => {{
        let head_ptr = $head as *mut $crate::criu::list::ListHead;
        let mut pos_list = unsafe { (*head_ptr).next };
        while pos_list != head_ptr {
            let $pos: *mut $ty = unsafe {
                $crate::criu::list::list_entry(pos_list, $crate::offset_of!($ty, $member))
            };
            $body
            pos_list = unsafe { (*pos_list).next };
        }
    }};
}

/// Iterate over list entries (safe version - allows removal during iteration).
/// Maps to: list_for_each_entry_safe
#[macro_export]
macro_rules! list_for_each_entry_safe {
    ($pos:ident, $head:expr, $ty:ty, $member:ident, $body:block) => {{
        let head_ptr = $head as *mut $crate::criu::list::ListHead;
        let mut pos_list = unsafe { (*head_ptr).next };
        while pos_list != head_ptr {
            let next_list = unsafe { (*pos_list).next };
            let $pos: *mut $ty = unsafe {
                $crate::criu::list::list_entry(pos_list, $crate::offset_of!($ty, $member))
            };
            $body
            pos_list = next_list;
        }
    }};
}

/// Hash list head - single pointer for hash table buckets.
/// Maps to: struct hlist_head (include/common/list.h)
#[repr(C)]
pub struct HlistHead {
    pub first: *mut HlistNode,
}

/// Hash list node - for entries in hash table.
/// Maps to: struct hlist_node (include/common/list.h)
#[repr(C)]
pub struct HlistNode {
    pub next: *mut HlistNode,
    pub pprev: *mut *mut HlistNode,
}

impl HlistHead {
    pub const fn new() -> Self {
        Self {
            first: ptr::null_mut(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.first.is_null()
    }

    /// Add node at head of hash list.
    /// Maps to: hlist_add_head
    #[inline]
    pub unsafe fn add_head(&mut self, n: *mut HlistNode) {
        let first = self.first;
        (*n).next = first;
        if !first.is_null() {
            (*first).pprev = &mut (*n).next;
        }
        self.first = n;
        (*n).pprev = &mut self.first;
    }
}

impl HlistNode {
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            pprev: ptr::null_mut(),
        }
    }

    #[inline]
    pub fn is_unhashed(&self) -> bool {
        self.pprev.is_null()
    }

    /// Delete node from hash list.
    /// Maps to: hlist_del
    #[inline]
    pub unsafe fn del(&mut self) {
        let next = self.next;
        let pprev = self.pprev;
        *pprev = next;
        if !next.is_null() {
            (*next).pprev = pprev;
        }
        self.next = POISON1 as *mut HlistNode;
        self.pprev = POISON2 as *mut *mut HlistNode;
    }

    /// Delete and reinitialize.
    /// Maps to: hlist_del_init
    #[inline]
    pub unsafe fn del_init(&mut self) {
        if !self.is_unhashed() {
            let next = self.next;
            let pprev = self.pprev;
            *pprev = next;
            if !next.is_null() {
                (*next).pprev = pprev;
            }
            self.next = ptr::null_mut();
            self.pprev = ptr::null_mut();
        }
    }
}

impl Default for HlistHead {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HlistNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct TestEntry {
        value: i32,
        list: ListHead,
    }

    #[test]
    fn test_list_init_empty() {
        let mut head = ListHead::uninit();
        head.init();
        assert!(head.is_empty());
    }

    #[test]
    fn test_list_add_not_empty() {
        let mut head = ListHead::uninit();
        head.init();

        let mut entry = TestEntry {
            value: 42,
            list: ListHead::uninit(),
        };
        entry.list.init();

        unsafe {
            head.add(&mut entry.list);
        }

        assert!(!head.is_empty());
    }

    #[test]
    fn test_list_entry_macro() {
        let mut entry = TestEntry {
            value: 42,
            list: ListHead::uninit(),
        };
        entry.list.init();

        let list_ptr = &mut entry.list as *mut ListHead;
        let recovered: *mut TestEntry =
            unsafe { list_entry(list_ptr, offset_of!(TestEntry, list)) };

        assert_eq!(unsafe { (*recovered).value }, 42);
    }

    #[test]
    fn test_list_iteration() {
        let mut head = ListHead::uninit();
        head.init();

        let mut entries = [
            TestEntry {
                value: 1,
                list: ListHead::uninit(),
            },
            TestEntry {
                value: 2,
                list: ListHead::uninit(),
            },
            TestEntry {
                value: 3,
                list: ListHead::uninit(),
            },
        ];

        for entry in &mut entries {
            entry.list.init();
            unsafe {
                head.add_tail(&mut entry.list);
            }
        }

        let mut sum = 0;
        list_for_each_entry!(pos, &mut head, TestEntry, list, {
            sum += unsafe { (*pos).value };
        });

        assert_eq!(sum, 6);
    }

    #[test]
    fn test_hlist_add_head() {
        let mut head = HlistHead::new();
        assert!(head.is_empty());

        let mut node = HlistNode::new();
        unsafe {
            head.add_head(&mut node);
        }

        assert!(!head.is_empty());
        assert!(!node.is_unhashed());
    }
}
