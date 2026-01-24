use std::io::{self, IoSlice};
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::Mutex;

use crate::criu::util::{read_all, write_all};

const BUFSIZE: usize = 4096;
const BUFBATCH: usize = 16;

struct BufPtr(*mut u8);
unsafe impl Send for BufPtr {}
unsafe impl Sync for BufPtr {}

static FLUSH_FAILED: Mutex<bool> = Mutex::new(false);
static BUF_POOL: Mutex<Vec<BufPtr>> = Mutex::new(Vec::new());

pub struct BfdBuf {
    pub mem: *mut u8,
}

pub struct Xbuf {
    pub mem: *mut u8,
    pub data: *mut u8,
    pub sz: usize,
    pub buf: Option<Box<BfdBuf>>,
}

impl Default for Xbuf {
    fn default() -> Self {
        Xbuf {
            mem: ptr::null_mut(),
            data: ptr::null_mut(),
            sz: 0,
            buf: None,
        }
    }
}

pub struct Bfd {
    pub fd: RawFd,
    pub writable: bool,
    pub b: Xbuf,
}

impl Bfd {
    pub fn new(fd: RawFd) -> Self {
        Bfd {
            fd,
            writable: false,
            b: Xbuf::default(),
        }
    }

    #[inline]
    pub fn buffered(&self) -> bool {
        !self.b.mem.is_null()
    }

    #[inline]
    pub fn setraw(&mut self) {
        self.b.mem = ptr::null_mut();
    }
}

fn buf_get(xb: &mut Xbuf) -> io::Result<()> {
    let mut pool = BUF_POOL.lock().unwrap();

    if pool.is_empty() {
        let mem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                BUFBATCH * BUFSIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mem == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        for i in 0..BUFBATCH {
            let buf_mem = unsafe { (mem as *mut u8).add(i * BUFSIZE) };
            pool.push(BufPtr(buf_mem));
        }
    }

    let BufPtr(mem) = pool.pop().unwrap();

    xb.mem = mem;
    xb.data = mem;
    xb.sz = 0;
    xb.buf = Some(Box::new(BfdBuf { mem }));

    Ok(())
}

fn buf_put(xb: &mut Xbuf) {
    // Don't unmap buffer back, it will get reused by next bfdopen call
    if let Some(buf) = xb.buf.take() {
        let mut pool = BUF_POOL.lock().unwrap();
        pool.push(BufPtr(buf.mem));
    }
    xb.mem = ptr::null_mut();
    xb.data = ptr::null_mut();
}

fn bfdopen(f: &mut Bfd, writable: bool) -> io::Result<()> {
    if buf_get(&mut f.b).is_err() {
        unsafe { libc::close(f.fd) };
        f.fd = -1;
        return Err(io::Error::new(io::ErrorKind::Other, "failed to get buffer"));
    }

    f.writable = writable;
    Ok(())
}

pub fn bfdopenr(f: &mut Bfd) -> io::Result<()> {
    bfdopen(f, false)
}

pub fn bfdopenw(f: &mut Bfd) -> io::Result<()> {
    bfdopen(f, true)
}

pub fn bclose(f: &mut Bfd) {
    if f.buffered() {
        if f.writable {
            if let Err(_) = bflush(f) {
                // This is to propagate error up. It's hardly possible by
                // returning and checking it, but setting a static flag,
                // failing further bfdopen-s and checking one at the end
                // would work.
                *FLUSH_FAILED.lock().unwrap() = true;
            }
        }

        buf_put(&mut f.b);
    }

    if f.fd >= 0 {
        unsafe { libc::close(f.fd) };
        f.fd = -1;
    }
}

pub fn bfd_flush_images() -> io::Result<()> {
    if *FLUSH_FAILED.lock().unwrap() {
        Err(io::Error::new(io::ErrorKind::Other, "flush failed"))
    } else {
        Ok(())
    }
}

pub fn bflush(bfd: &mut Bfd) -> io::Result<()> {
    let b = &mut bfd.b;

    if b.sz == 0 {
        return Ok(());
    }

    let data = unsafe { std::slice::from_raw_parts(b.data, b.sz) };
    let ret = write_all(bfd.fd, data)?;

    if ret != b.sz {
        return Err(io::Error::new(io::ErrorKind::Other, "short write"));
    }

    b.sz = 0;
    Ok(())
}

fn brefill(f: &mut Bfd) -> io::Result<i32> {
    let b = &mut f.b;

    if b.sz > 0 && b.data != b.mem {
        unsafe {
            ptr::copy(b.data, b.mem, b.sz);
        }
    }
    b.data = b.mem;

    let space = BUFSIZE - b.sz;
    let buf = unsafe { std::slice::from_raw_parts_mut(b.mem.add(b.sz), space) };
    let ret = read_all(f.fd, buf)?;

    if ret == 0 {
        return Ok(0);
    }

    b.sz += ret;
    Ok(1)
}

fn strnchr(data: *const u8, len: usize, c: u8) -> Option<*const u8> {
    for i in 0..len {
        let ch = unsafe { *data.add(i) };
        if ch == c {
            return Some(unsafe { data.add(i) });
        }
    }
    None
}

pub fn breadchr(f: &mut Bfd, c: u8) -> io::Result<Option<&[u8]>> {
    let mut refilled = false;
    let mut skip = 0;

    loop {
        let b = &mut f.b;

        if let Some(pos) = strnchr(unsafe { b.data.add(skip) }, b.sz - skip, c) {
            let start = b.data;
            let len = unsafe { pos.offset_from(start) as usize };

            let ret_slice = unsafe { std::slice::from_raw_parts(start, len) };
            b.data = unsafe { (pos as *mut u8).add(1) };
            b.sz -= len + 1;

            return Ok(Some(ret_slice));
        }

        if refilled {
            if b.sz == 0 {
                return Ok(None);
            }

            if b.sz == BUFSIZE {
                return Err(io::Error::new(io::ErrorKind::Other, "buffer too small"));
            }

            let ret_slice = unsafe { std::slice::from_raw_parts(b.data, b.sz) };
            b.sz = 0;
            return Ok(Some(ret_slice));
        }

        skip = b.sz;

        if brefill(f)? < 0 {
            return Err(io::Error::last_os_error());
        }

        refilled = true;
    }
}

pub fn breadline(f: &mut Bfd) -> io::Result<Option<&[u8]>> {
    breadchr(f, b'\n')
}

pub fn __bwrite(bfd: &mut Bfd, buf: &[u8]) -> io::Result<usize> {
    if bfd.b.sz + buf.len() > BUFSIZE {
        bflush(bfd)?;
    }

    if buf.len() > BUFSIZE {
        return write_all(bfd.fd, buf);
    }

    unsafe {
        ptr::copy_nonoverlapping(buf.as_ptr(), bfd.b.data.add(bfd.b.sz), buf.len());
    }
    bfd.b.sz += buf.len();

    Ok(buf.len())
}

pub fn bwrite(bfd: &mut Bfd, buf: &[u8]) -> io::Result<usize> {
    if !bfd.buffered() {
        return write_all(bfd.fd, buf);
    }

    __bwrite(bfd, buf)
}

pub fn bwritev(bfd: &mut Bfd, iov: &[IoSlice<'_>]) -> io::Result<usize> {
    if !bfd.buffered() {
        // FIXME: writev() should be called again if writev() writes
        // less bytes than requested.
        let ret = unsafe {
            libc::writev(
                bfd.fd,
                iov.as_ptr() as *const libc::iovec,
                iov.len() as libc::c_int,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(ret as usize);
    }

    let mut written = 0;
    for slice in iov {
        let ret = __bwrite(bfd, slice)?;
        written += ret;
        if ret < slice.len() {
            break;
        }
    }

    Ok(written)
}

pub fn bread(bfd: &mut Bfd, buf: &mut [u8]) -> io::Result<usize> {
    if !bfd.buffered() {
        return read_all(bfd.fd, buf);
    }

    let mut filled = 0;

    loop {
        let b = &mut bfd.b;

        let chunk = std::cmp::min(buf.len() - filled, b.sz);
        if chunk > 0 {
            unsafe {
                ptr::copy_nonoverlapping(b.data, buf.as_mut_ptr().add(filled), chunk);
            }
            b.data = unsafe { b.data.add(chunk) };
            b.sz -= chunk;
            filled += chunk;
        }

        if filled >= buf.len() {
            return Ok(filled);
        }

        let more = brefill(bfd)?;
        if more <= 0 {
            return Ok(filled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path(prefix: &str) -> String {
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("/tmp/bfd_test_{}_{}", prefix, count)
    }

    fn create_temp_file(content: &[u8]) -> (RawFd, String) {
        let path = unique_path("r");
        fs::write(&path, content).unwrap();
        let c_path = CString::new(path.clone()).unwrap();
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "Failed to open {}", path);
        (fd, path)
    }

    fn create_temp_file_for_write() -> (RawFd, String) {
        let path = unique_path("w");
        let c_path = CString::new(path.clone()).unwrap();
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
        };
        assert!(fd >= 0, "Failed to create {}", path);
        (fd, path)
    }

    #[test]
    fn test_strnchr_found() {
        let data = b"hello\nworld";
        let result = strnchr(data.as_ptr(), data.len(), b'\n');
        assert!(result.is_some());
        let pos = unsafe { result.unwrap().offset_from(data.as_ptr()) };
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_strnchr_not_found() {
        let data = b"hello world";
        let result = strnchr(data.as_ptr(), data.len(), b'\n');
        assert!(result.is_none());
    }

    #[test]
    fn test_strnchr_at_start() {
        let data = b"\nhello";
        let result = strnchr(data.as_ptr(), data.len(), b'\n');
        assert!(result.is_some());
        let pos = unsafe { result.unwrap().offset_from(data.as_ptr()) };
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_bfd_new() {
        let bfd = Bfd::new(5);
        assert_eq!(bfd.fd, 5);
        assert!(!bfd.writable);
        assert!(!bfd.buffered());
    }

    #[test]
    fn test_bfdopenr_and_bclose() {
        let (fd, path) = create_temp_file(b"test data");
        let mut bfd = Bfd::new(fd);

        let result = bfdopenr(&mut bfd);
        assert!(result.is_ok());
        assert!(bfd.buffered());
        assert!(!bfd.writable);

        bclose(&mut bfd);
        assert!(!bfd.buffered());
        assert_eq!(bfd.fd, -1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bfdopenw_and_bclose() {
        let (fd, path) = create_temp_file_for_write();
        let mut bfd = Bfd::new(fd);

        let result = bfdopenw(&mut bfd);
        assert!(result.is_ok());
        assert!(bfd.buffered());
        assert!(bfd.writable);

        bclose(&mut bfd);
        assert!(!bfd.buffered());
        assert_eq!(bfd.fd, -1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bread_basic() {
        let content = b"hello world";
        let (fd, path) = create_temp_file(content);
        let mut bfd = Bfd::new(fd);
        bfdopenr(&mut bfd).unwrap();

        let mut buf = [0u8; 11];
        let n = bread(&mut bfd, &mut buf).unwrap();

        assert_eq!(n, 11);
        assert_eq!(&buf, content);

        bclose(&mut bfd);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bread_partial() {
        let content = b"hello world test data";
        let (fd, path) = create_temp_file(content);
        let mut bfd = Bfd::new(fd);
        bfdopenr(&mut bfd).unwrap();

        let mut buf1 = [0u8; 5];
        let n1 = bread(&mut bfd, &mut buf1).unwrap();
        assert_eq!(n1, 5);
        assert_eq!(&buf1, b"hello");

        let mut buf2 = [0u8; 6];
        let n2 = bread(&mut bfd, &mut buf2).unwrap();
        assert_eq!(n2, 6);
        assert_eq!(&buf2, b" world");

        bclose(&mut bfd);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bwrite_and_read_back() {
        let (fd, path) = create_temp_file_for_write();
        let mut bfd = Bfd::new(fd);
        bfdopenw(&mut bfd).unwrap();

        let data = b"test write data";
        let n = bwrite(&mut bfd, data).unwrap();
        assert_eq!(n, data.len());

        bclose(&mut bfd);

        // Read back and verify
        let content = fs::read(&path).unwrap();
        assert_eq!(&content, data);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bwrite_multiple() {
        let (fd, path) = create_temp_file_for_write();
        let mut bfd = Bfd::new(fd);
        bfdopenw(&mut bfd).unwrap();

        bwrite(&mut bfd, b"hello ").unwrap();
        bwrite(&mut bfd, b"world").unwrap();

        bclose(&mut bfd);

        let content = fs::read(&path).unwrap();
        assert_eq!(&content, b"hello world");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_breadline() {
        let content = b"line1\nline2\nline3";
        let (fd, path) = create_temp_file(content);
        let mut bfd = Bfd::new(fd);
        bfdopenr(&mut bfd).unwrap();

        let line1 = breadline(&mut bfd).unwrap().unwrap();
        assert_eq!(line1, b"line1");

        let line2 = breadline(&mut bfd).unwrap().unwrap();
        assert_eq!(line2, b"line2");

        let line3 = breadline(&mut bfd).unwrap().unwrap();
        assert_eq!(line3, b"line3");

        bclose(&mut bfd);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_breadchr() {
        let content = b"key:value:extra";
        let (fd, path) = create_temp_file(content);
        let mut bfd = Bfd::new(fd);
        bfdopenr(&mut bfd).unwrap();

        let part1 = breadchr(&mut bfd, b':').unwrap().unwrap();
        assert_eq!(part1, b"key");

        let part2 = breadchr(&mut bfd, b':').unwrap().unwrap();
        assert_eq!(part2, b"value");

        let part3 = breadchr(&mut bfd, b':').unwrap().unwrap();
        assert_eq!(part3, b"extra");

        bclose(&mut bfd);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bwritev() {
        let (fd, path) = create_temp_file_for_write();
        let mut bfd = Bfd::new(fd);
        bfdopenw(&mut bfd).unwrap();

        let data1 = b"hello ";
        let data2 = b"world";
        let iov = [IoSlice::new(data1), IoSlice::new(data2)];

        let n = bwritev(&mut bfd, &iov).unwrap();
        assert_eq!(n, 11);

        bclose(&mut bfd);

        let content = fs::read(&path).unwrap();
        assert_eq!(&content, b"hello world");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_bflush() {
        let (fd, path) = create_temp_file_for_write();
        let mut bfd = Bfd::new(fd);
        bfdopenw(&mut bfd).unwrap();

        bwrite(&mut bfd, b"before flush").unwrap();
        bflush(&mut bfd).unwrap();

        // Data should be on disk after flush
        let content = fs::read(&path).unwrap();
        assert_eq!(&content, b"before flush");

        bclose(&mut bfd);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_setraw() {
        let (fd, path) = create_temp_file(b"test");
        let mut bfd = Bfd::new(fd);
        bfdopenr(&mut bfd).unwrap();

        assert!(bfd.buffered());
        bfd.setraw();
        assert!(!bfd.buffered());

        // Clean up - need to close fd manually since setraw doesn't return buffer
        unsafe { libc::close(fd) };
        fs::remove_file(&path).ok();
    }
}
