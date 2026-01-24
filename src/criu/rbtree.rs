use std::ptr::NonNull;

const RB_RED: usize = 0;
const RB_BLACK: usize = 1;
const RB_MASK: usize = 3;

/// Red-black tree node.
///
/// Adopted from Linux kernel implementation via CRIU.
/// Uses pointer tagging: lower 2 bits of rb_parent_color store color,
/// upper bits store parent pointer (works because pointers are aligned).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RbNode {
    rb_parent_color: usize,
    pub rb_right: Option<NonNull<RbNode>>,
    pub rb_left: Option<NonNull<RbNode>>,
}

/// Red-black tree root.
#[repr(C)]
pub struct RbRoot {
    pub rb_node: Option<NonNull<RbNode>>,
}

impl Default for RbRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl RbRoot {
    pub const fn new() -> Self {
        RbRoot { rb_node: None }
    }

    pub fn is_empty(&self) -> bool {
        self.rb_node.is_none()
    }
}

impl RbNode {
    pub const fn new() -> Self {
        RbNode {
            rb_parent_color: 0,
            rb_right: None,
            rb_left: None,
        }
    }

    #[inline]
    fn parent(&self) -> Option<NonNull<RbNode>> {
        let ptr = (self.rb_parent_color & !RB_MASK) as *mut RbNode;
        NonNull::new(ptr)
    }

    #[inline]
    fn color(&self) -> usize {
        self.rb_parent_color & RB_BLACK
    }

    #[inline]
    fn is_red(&self) -> bool {
        self.color() == RB_RED
    }

    #[inline]
    fn is_black(&self) -> bool {
        self.color() == RB_BLACK
    }

    #[inline]
    fn set_red(&mut self) {
        self.rb_parent_color &= !RB_BLACK;
    }

    #[inline]
    fn set_black(&mut self) {
        self.rb_parent_color |= RB_BLACK;
    }

    #[inline]
    fn set_parent(&mut self, parent: Option<NonNull<RbNode>>) {
        let ptr = parent.map(|p| p.as_ptr() as usize).unwrap_or(0);
        self.rb_parent_color = (self.rb_parent_color & RB_MASK) | ptr;
    }

    #[inline]
    fn set_color(&mut self, color: usize) {
        self.rb_parent_color = (self.rb_parent_color & !RB_BLACK) | color;
    }

    /// Initialize node as cleared (parent points to self).
    pub fn init(&mut self) {
        self.rb_parent_color = 0;
        self.rb_right = None;
        self.rb_left = None;
        self.clear();
    }

    /// Clear node by setting parent to self (sentinel value).
    pub fn clear(&mut self) {
        let self_ptr = self as *mut RbNode as usize;
        self.rb_parent_color = (self.rb_parent_color & RB_MASK) | self_ptr;
    }

    /// Check if node is empty (parent == self).
    pub fn is_empty(&self) -> bool {
        let self_ptr = self as *const RbNode as usize;
        (self.rb_parent_color & !RB_MASK) == self_ptr
    }
}

fn rotate_left(node: NonNull<RbNode>, root: &mut RbRoot) {
    unsafe {
        let node_ptr = node.as_ptr();
        let right = (*node_ptr).rb_right.unwrap();
        let right_ptr = right.as_ptr();
        let parent = (*node_ptr).parent();

        (*node_ptr).rb_right = (*right_ptr).rb_left;
        if let Some(right_left) = (*node_ptr).rb_right {
            (*right_left.as_ptr()).set_parent(Some(node));
        }
        (*right_ptr).rb_left = Some(node);

        (*right_ptr).set_parent(parent);

        if let Some(parent) = parent {
            if (*parent.as_ptr()).rb_left == Some(node) {
                (*parent.as_ptr()).rb_left = Some(right);
            } else {
                (*parent.as_ptr()).rb_right = Some(right);
            }
        } else {
            root.rb_node = Some(right);
        }
        (*node_ptr).set_parent(Some(right));
    }
}

fn rotate_right(node: NonNull<RbNode>, root: &mut RbRoot) {
    unsafe {
        let node_ptr = node.as_ptr();
        let left = (*node_ptr).rb_left.unwrap();
        let left_ptr = left.as_ptr();
        let parent = (*node_ptr).parent();

        (*node_ptr).rb_left = (*left_ptr).rb_right;
        if let Some(left_right) = (*node_ptr).rb_left {
            (*left_right.as_ptr()).set_parent(Some(node));
        }
        (*left_ptr).rb_right = Some(node);

        (*left_ptr).set_parent(parent);

        if let Some(parent) = parent {
            if (*parent.as_ptr()).rb_right == Some(node) {
                (*parent.as_ptr()).rb_right = Some(left);
            } else {
                (*parent.as_ptr()).rb_left = Some(left);
            }
        } else {
            root.rb_node = Some(left);
        }
        (*node_ptr).set_parent(Some(left));
    }
}

/// Insert a node and rebalance the tree.
///
/// The node must already be linked via rb_link_node.
pub fn rb_insert_color(node: NonNull<RbNode>, root: &mut RbRoot) {
    unsafe {
        let mut node = node;

        while let Some(parent) = (*node.as_ptr()).parent() {
            if !(*parent.as_ptr()).is_red() {
                break;
            }

            let gparent = (*parent.as_ptr()).parent().unwrap();

            if Some(parent) == (*gparent.as_ptr()).rb_left {
                let uncle = (*gparent.as_ptr()).rb_right;
                if let Some(uncle) = uncle {
                    if (*uncle.as_ptr()).is_red() {
                        (*uncle.as_ptr()).set_black();
                        (*parent.as_ptr()).set_black();
                        (*gparent.as_ptr()).set_red();
                        node = gparent;
                        continue;
                    }
                }

                if (*parent.as_ptr()).rb_right == Some(node) {
                    rotate_left(parent, root);
                    let tmp = parent;
                    let _parent = node;
                    node = tmp;
                }

                let parent = (*node.as_ptr()).parent().unwrap();
                let gparent = (*parent.as_ptr()).parent().unwrap();
                (*parent.as_ptr()).set_black();
                (*gparent.as_ptr()).set_red();
                rotate_right(gparent, root);
            } else {
                let uncle = (*gparent.as_ptr()).rb_left;
                if let Some(uncle) = uncle {
                    if (*uncle.as_ptr()).is_red() {
                        (*uncle.as_ptr()).set_black();
                        (*parent.as_ptr()).set_black();
                        (*gparent.as_ptr()).set_red();
                        node = gparent;
                        continue;
                    }
                }

                if (*parent.as_ptr()).rb_left == Some(node) {
                    rotate_right(parent, root);
                    let tmp = parent;
                    let _parent = node;
                    node = tmp;
                }

                let parent = (*node.as_ptr()).parent().unwrap();
                let gparent = (*parent.as_ptr()).parent().unwrap();
                (*parent.as_ptr()).set_black();
                (*gparent.as_ptr()).set_red();
                rotate_left(gparent, root);
            }
        }

        (*root.rb_node.unwrap().as_ptr()).set_black();
    }
}

fn erase_color(node: Option<NonNull<RbNode>>, mut parent: Option<NonNull<RbNode>>, root: &mut RbRoot) {
    unsafe {
        let mut node = node;

        loop {
            if let Some(n) = node {
                if (*n.as_ptr()).is_red() || Some(n) == root.rb_node {
                    break;
                }
            } else if node.is_none() && (parent.is_none() || root.rb_node.is_none()) {
                break;
            }

            let parent_ptr = parent.unwrap().as_ptr();

            if node == (*parent_ptr).rb_left {
                let mut other = (*parent_ptr).rb_right.unwrap();
                if (*other.as_ptr()).is_red() {
                    (*other.as_ptr()).set_black();
                    (*parent_ptr).set_red();
                    rotate_left(parent.unwrap(), root);
                    other = (*parent_ptr).rb_right.unwrap();
                }
                let other_left_black = (*other.as_ptr()).rb_left.map(|n| (*n.as_ptr()).is_black()).unwrap_or(true);
                let other_right_black = (*other.as_ptr()).rb_right.map(|n| (*n.as_ptr()).is_black()).unwrap_or(true);
                if other_left_black && other_right_black {
                    (*other.as_ptr()).set_red();
                    node = parent;
                    parent = (*parent_ptr).parent();
                } else {
                    if other_right_black {
                        if let Some(ol) = (*other.as_ptr()).rb_left {
                            (*ol.as_ptr()).set_black();
                        }
                        (*other.as_ptr()).set_red();
                        rotate_right(other, root);
                        other = (*parent_ptr).rb_right.unwrap();
                    }
                    (*other.as_ptr()).set_color((*parent_ptr).color());
                    (*parent_ptr).set_black();
                    if let Some(or) = (*other.as_ptr()).rb_right {
                        (*or.as_ptr()).set_black();
                    }
                    rotate_left(parent.unwrap(), root);
                    node = root.rb_node;
                    break;
                }
            } else {
                let mut other = (*parent_ptr).rb_left.unwrap();
                if (*other.as_ptr()).is_red() {
                    (*other.as_ptr()).set_black();
                    (*parent_ptr).set_red();
                    rotate_right(parent.unwrap(), root);
                    other = (*parent_ptr).rb_left.unwrap();
                }
                let other_left_black = (*other.as_ptr()).rb_left.map(|n| (*n.as_ptr()).is_black()).unwrap_or(true);
                let other_right_black = (*other.as_ptr()).rb_right.map(|n| (*n.as_ptr()).is_black()).unwrap_or(true);
                if other_left_black && other_right_black {
                    (*other.as_ptr()).set_red();
                    node = parent;
                    parent = (*parent_ptr).parent();
                } else {
                    if other_left_black {
                        if let Some(or) = (*other.as_ptr()).rb_right {
                            (*or.as_ptr()).set_black();
                        }
                        (*other.as_ptr()).set_red();
                        rotate_left(other, root);
                        other = (*parent_ptr).rb_left.unwrap();
                    }
                    (*other.as_ptr()).set_color((*parent_ptr).color());
                    (*parent_ptr).set_black();
                    if let Some(ol) = (*other.as_ptr()).rb_left {
                        (*ol.as_ptr()).set_black();
                    }
                    rotate_right(parent.unwrap(), root);
                    node = root.rb_node;
                    break;
                }
            }
        }

        if let Some(n) = node {
            (*n.as_ptr()).set_black();
        }
    }
}

/// Remove a node from the tree.
pub fn rb_erase(node: NonNull<RbNode>, root: &mut RbRoot) {
    unsafe {
        let node_ptr = node.as_ptr();
        let child: Option<NonNull<RbNode>>;
        let mut parent: Option<NonNull<RbNode>>;
        let color: usize;

        if (*node_ptr).rb_left.is_none() {
            child = (*node_ptr).rb_right;
            parent = (*node_ptr).parent();
            color = (*node_ptr).color();

            if let Some(c) = child {
                (*c.as_ptr()).set_parent(parent);
            }

            if let Some(p) = parent {
                if (*p.as_ptr()).rb_left == Some(node) {
                    (*p.as_ptr()).rb_left = child;
                } else {
                    (*p.as_ptr()).rb_right = child;
                }
            } else {
                root.rb_node = child;
            }
        } else if (*node_ptr).rb_right.is_none() {
            child = (*node_ptr).rb_left;
            parent = (*node_ptr).parent();
            color = (*node_ptr).color();

            if let Some(c) = child {
                (*c.as_ptr()).set_parent(parent);
            }

            if let Some(p) = parent {
                if (*p.as_ptr()).rb_left == Some(node) {
                    (*p.as_ptr()).rb_left = child;
                } else {
                    (*p.as_ptr()).rb_right = child;
                }
            } else {
                root.rb_node = child;
            }
        } else {
            let old = node;
            let old_ptr = old.as_ptr();

            let mut successor = (*node_ptr).rb_right.unwrap();
            while let Some(left) = (*successor.as_ptr()).rb_left {
                successor = left;
            }

            if let Some(old_parent) = (*old_ptr).parent() {
                if (*old_parent.as_ptr()).rb_left == Some(old) {
                    (*old_parent.as_ptr()).rb_left = Some(successor);
                } else {
                    (*old_parent.as_ptr()).rb_right = Some(successor);
                }
            } else {
                root.rb_node = Some(successor);
            }

            child = (*successor.as_ptr()).rb_right;
            parent = (*successor.as_ptr()).parent();
            color = (*successor.as_ptr()).color();

            if parent == Some(old) {
                parent = Some(successor);
            } else {
                if let Some(c) = child {
                    (*c.as_ptr()).set_parent(parent);
                }
                (*parent.unwrap().as_ptr()).rb_left = child;

                (*successor.as_ptr()).rb_right = (*old_ptr).rb_right;
                (*(*old_ptr).rb_right.unwrap().as_ptr()).set_parent(Some(successor));
            }

            (*successor.as_ptr()).rb_parent_color = (*old_ptr).rb_parent_color;
            (*successor.as_ptr()).rb_left = (*old_ptr).rb_left;
            (*(*old_ptr).rb_left.unwrap().as_ptr()).set_parent(Some(successor));

            if color == RB_BLACK {
                erase_color(child, parent, root);
            }
            return;
        }

        if color == RB_BLACK {
            erase_color(child, parent, root);
        }
    }
}

/// Returns the first (leftmost) node in the tree.
pub fn rb_first(root: &RbRoot) -> Option<NonNull<RbNode>> {
    unsafe {
        let mut n = root.rb_node?;
        while let Some(left) = (*n.as_ptr()).rb_left {
            n = left;
        }
        Some(n)
    }
}

/// Returns the last (rightmost) node in the tree.
pub fn rb_last(root: &RbRoot) -> Option<NonNull<RbNode>> {
    unsafe {
        let mut n = root.rb_node?;
        while let Some(right) = (*n.as_ptr()).rb_right {
            n = right;
        }
        Some(n)
    }
}

/// Returns the next node in sort order.
pub fn rb_next(node: NonNull<RbNode>) -> Option<NonNull<RbNode>> {
    unsafe {
        let node_ptr = node.as_ptr();

        if (*node_ptr).is_empty() {
            return None;
        }

        if let Some(right) = (*node_ptr).rb_right {
            let mut n = right;
            while let Some(left) = (*n.as_ptr()).rb_left {
                n = left;
            }
            return Some(n);
        }

        let mut current = node;
        while let Some(parent) = (*current.as_ptr()).parent() {
            if (*parent.as_ptr()).rb_right != Some(current) {
                return Some(parent);
            }
            current = parent;
        }

        None
    }
}

/// Returns the previous node in sort order.
pub fn rb_prev(node: NonNull<RbNode>) -> Option<NonNull<RbNode>> {
    unsafe {
        let node_ptr = node.as_ptr();

        if (*node_ptr).is_empty() {
            return None;
        }

        if let Some(left) = (*node_ptr).rb_left {
            let mut n = left;
            while let Some(right) = (*n.as_ptr()).rb_right {
                n = right;
            }
            return Some(n);
        }

        let mut current = node;
        while let Some(parent) = (*current.as_ptr()).parent() {
            if (*parent.as_ptr()).rb_left != Some(current) {
                return Some(parent);
            }
            current = parent;
        }

        None
    }
}

/// Replace a node with another without rebalancing.
pub fn rb_replace_node(victim: NonNull<RbNode>, new: NonNull<RbNode>, root: &mut RbRoot) {
    unsafe {
        let victim_ptr = victim.as_ptr();
        let new_ptr = new.as_ptr();

        if let Some(parent) = (*victim_ptr).parent() {
            if (*parent.as_ptr()).rb_left == Some(victim) {
                (*parent.as_ptr()).rb_left = Some(new);
            } else {
                (*parent.as_ptr()).rb_right = Some(new);
            }
        } else {
            root.rb_node = Some(new);
        }

        if let Some(left) = (*victim_ptr).rb_left {
            (*left.as_ptr()).set_parent(Some(new));
        }

        if let Some(right) = (*victim_ptr).rb_right {
            (*right.as_ptr()).set_parent(Some(new));
        }

        *new_ptr = *victim_ptr;
    }
}

/// Link a node to a parent, preparing for rb_insert_color.
pub fn rb_link_node(node: NonNull<RbNode>, parent: Option<NonNull<RbNode>>, rb_link: &mut Option<NonNull<RbNode>>) {
    unsafe {
        let node_ptr = node.as_ptr();
        (*node_ptr).rb_parent_color = parent.map(|p| p.as_ptr() as usize).unwrap_or(0);
        (*node_ptr).rb_left = None;
        (*node_ptr).rb_right = None;
        *rb_link = Some(node);
    }
}

/// Link and balance in one operation.
pub fn rb_link_and_balance(root: &mut RbRoot, node: NonNull<RbNode>, parent: Option<NonNull<RbNode>>, rb_link: &mut Option<NonNull<RbNode>>) {
    rb_link_node(node, parent, rb_link);
    rb_insert_color(node, root);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{alloc, dealloc, Layout};

    struct TestNode {
        rb: RbNode,
        key: i32,
    }

    fn alloc_test_node(key: i32) -> *mut TestNode {
        unsafe {
            let layout = Layout::new::<TestNode>();
            let ptr = alloc(layout) as *mut TestNode;
            (*ptr).rb = RbNode::new();
            (*ptr).rb.init();
            (*ptr).key = key;
            ptr
        }
    }

    fn free_test_node(ptr: *mut TestNode) {
        unsafe {
            let layout = Layout::new::<TestNode>();
            dealloc(ptr as *mut u8, layout);
        }
    }

    fn insert_node(root: &mut RbRoot, node: *mut TestNode) {
        unsafe {
            let key = (*node).key;
            let mut parent: Option<NonNull<RbNode>> = None;
            let mut link: *mut Option<NonNull<RbNode>> = &mut root.rb_node;

            while let Some(curr) = *link {
                let curr_node = (curr.as_ptr() as *mut u8).sub(0) as *mut TestNode;
                parent = Some(curr);
                if key < (*curr_node).key {
                    link = &mut (*curr.as_ptr()).rb_left;
                } else {
                    link = &mut (*curr.as_ptr()).rb_right;
                }
            }

            let node_nn = NonNull::new(&mut (*node).rb).unwrap();
            rb_link_and_balance(root, node_nn, parent, &mut *link);
        }
    }

    #[test]
    fn test_empty_root() {
        let root = RbRoot::new();
        assert!(root.is_empty());
        assert!(rb_first(&root).is_none());
        assert!(rb_last(&root).is_none());
    }

    #[test]
    fn test_single_insert() {
        let mut root = RbRoot::new();
        let node = alloc_test_node(10);

        insert_node(&mut root, node);

        assert!(!root.is_empty());
        assert!(rb_first(&root).is_some());
        assert!(rb_last(&root).is_some());

        free_test_node(node);
    }

    #[test]
    fn test_multiple_inserts_ascending() {
        let mut root = RbRoot::new();
        let nodes: Vec<*mut TestNode> = (0..10).map(|i| alloc_test_node(i)).collect();

        for &node in &nodes {
            insert_node(&mut root, node);
        }

        unsafe {
            let first = rb_first(&root).unwrap();
            let first_node = first.as_ptr() as *mut TestNode;
            assert_eq!((*first_node).key, 0);

            let last = rb_last(&root).unwrap();
            let last_node = last.as_ptr() as *mut TestNode;
            assert_eq!((*last_node).key, 9);
        }

        for node in nodes {
            free_test_node(node);
        }
    }

    #[test]
    fn test_multiple_inserts_descending() {
        let mut root = RbRoot::new();
        let nodes: Vec<*mut TestNode> = (0..10).rev().map(|i| alloc_test_node(i)).collect();

        for &node in &nodes {
            insert_node(&mut root, node);
        }

        unsafe {
            let first = rb_first(&root).unwrap();
            let first_node = first.as_ptr() as *mut TestNode;
            assert_eq!((*first_node).key, 0);

            let last = rb_last(&root).unwrap();
            let last_node = last.as_ptr() as *mut TestNode;
            assert_eq!((*last_node).key, 9);
        }

        for node in nodes {
            free_test_node(node);
        }
    }

    #[test]
    fn test_iteration() {
        let mut root = RbRoot::new();
        let keys = [5, 3, 7, 1, 4, 6, 8, 0, 2, 9];
        let nodes: Vec<*mut TestNode> = keys.iter().map(|&k| alloc_test_node(k)).collect();

        for &node in &nodes {
            insert_node(&mut root, node);
        }

        unsafe {
            let mut current = rb_first(&root);
            let mut collected = Vec::new();
            while let Some(node) = current {
                let test_node = node.as_ptr() as *mut TestNode;
                collected.push((*test_node).key);
                current = rb_next(node);
            }
            assert_eq!(collected, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        }

        for node in nodes {
            free_test_node(node);
        }
    }

    #[test]
    fn test_reverse_iteration() {
        let mut root = RbRoot::new();
        let keys = [5, 3, 7, 1, 4, 6, 8, 0, 2, 9];
        let nodes: Vec<*mut TestNode> = keys.iter().map(|&k| alloc_test_node(k)).collect();

        for &node in &nodes {
            insert_node(&mut root, node);
        }

        unsafe {
            let mut current = rb_last(&root);
            let mut collected = Vec::new();
            while let Some(node) = current {
                let test_node = node.as_ptr() as *mut TestNode;
                collected.push((*test_node).key);
                current = rb_prev(node);
            }
            assert_eq!(collected, vec![9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        }

        for node in nodes {
            free_test_node(node);
        }
    }

    #[test]
    fn test_erase() {
        let mut root = RbRoot::new();
        let nodes: Vec<*mut TestNode> = (0..5).map(|i| alloc_test_node(i)).collect();

        for &node in &nodes {
            insert_node(&mut root, node);
        }

        unsafe {
            let node_ptr = nodes[2];
            let node_to_remove = NonNull::new(&mut (*node_ptr).rb).unwrap();
            rb_erase(node_to_remove, &mut root);

            let mut current = rb_first(&root);
            let mut collected = Vec::new();
            while let Some(node) = current {
                let test_node = node.as_ptr() as *mut TestNode;
                collected.push((*test_node).key);
                current = rb_next(node);
            }
            assert_eq!(collected, vec![0, 1, 3, 4]);
        }

        for node in nodes {
            free_test_node(node);
        }
    }

    #[test]
    fn test_node_is_empty() {
        let mut node = RbNode::new();
        node.init();
        assert!(node.is_empty());
    }
}
