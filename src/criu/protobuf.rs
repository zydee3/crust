use std::io::{self, IoSlice};
use std::os::unix::io::RawFd;

use prost::Message;

use crate::criu::bfd::{bread, bwritev};
use crate::criu::image::{open_image_lazy, CrImg, LAZY_IMG_FD};
use crate::criu::util::{read_all, write_all};

const PB_PKOBJ_LOCAL_SIZE: usize = 1024;

pub fn pb_write_one<M: Message>(
    img: &mut CrImg,
    obj: &M,
    dfd: RawFd,
    type_magic: u32,
) -> io::Result<()> {
    if img.bfd.fd == LAZY_IMG_FD {
        open_image_lazy(img, dfd, type_magic)?;
    }

    let size = obj.encoded_len();

    let mut local_buf = [0u8; PB_PKOBJ_LOCAL_SIZE];
    let mut heap_buf: Vec<u8>;
    let buf: &mut [u8] = if size <= PB_PKOBJ_LOCAL_SIZE {
        &mut local_buf[..size]
    } else {
        heap_buf = vec![0u8; size];
        &mut heap_buf[..]
    };

    obj.encode(&mut &mut buf[..]).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed packing PB object: {}", e))
    })?;

    let size_bytes = (size as u32).to_ne_bytes();
    let iov = [IoSlice::new(&size_bytes), IoSlice::new(buf)];

    let expected = size_bytes.len() + size;
    let ret = bwritev(&mut img.bfd, &iov)?;

    if ret != expected {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Can't write {} bytes (wrote {})", expected, ret),
        ));
    }

    Ok(())
}

pub fn do_pb_read_one<M: Message + Default>(
    img: &mut CrImg,
    eof: bool,
) -> io::Result<Option<M>> {
    if img.is_empty() {
        if eof {
            return Ok(None);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF on image",
            ));
        }
    }

    let mut size_buf = [0u8; 4];
    let ret = bread(&mut img.bfd, &mut size_buf)?;

    if ret == 0 {
        if eof {
            return Ok(None);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF on image",
            ));
        }
    } else if ret < size_buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Read {} bytes while {} expected", ret, size_buf.len()),
        ));
    }

    let size = u32::from_ne_bytes(size_buf) as usize;

    let mut local_buf = [0u8; PB_PKOBJ_LOCAL_SIZE];
    let mut heap_buf: Vec<u8>;
    let buf: &mut [u8] = if size <= PB_PKOBJ_LOCAL_SIZE {
        &mut local_buf[..size]
    } else {
        heap_buf = vec![0u8; size];
        &mut heap_buf[..]
    };

    let ret = bread(&mut img.bfd, buf)?;

    if ret < size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Read {} bytes while {} expected", ret, size),
        ));
    }

    let msg = M::decode(&buf[..size]).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed unpacking PB object: {}", e))
    })?;

    Ok(Some(msg))
}

pub fn pb_read_one<M: Message + Default>(img: &mut CrImg) -> io::Result<M> {
    do_pb_read_one(img, false)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF"))
}

pub fn pb_read_one_eof<M: Message + Default>(img: &mut CrImg) -> io::Result<Option<M>> {
    do_pb_read_one(img, true)
}

pub fn pb_read_one_fd<M: Message + Default>(fd: RawFd) -> io::Result<M> {
    let mut size_buf = [0u8; 4];
    let ret = read_all(fd, &mut size_buf)?;

    if ret < size_buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to communicate with the image streamer",
        ));
    }

    let size = u32::from_ne_bytes(size_buf) as usize;

    let mut buf = vec![0u8; size];
    let ret = read_all(fd, &mut buf)?;

    if ret < size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to communicate with the image streamer",
        ));
    }

    M::decode(&buf[..]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to communicate with the image streamer: {}", e),
        )
    })
}

pub fn pb_write_one_fd<M: Message>(fd: RawFd, obj: &M) -> io::Result<()> {
    let size = obj.encoded_len();

    let mut buf = vec![0u8; size];
    obj.encode(&mut &mut buf[..]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to communicate with the image streamer: {}", e),
        )
    })?;

    let size_bytes = (size as u32).to_ne_bytes();
    let ret = write_all(fd, &size_bytes)?;

    if ret < size_bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to communicate with the image streamer",
        ));
    }

    let ret = write_all(fd, &buf)?;

    if ret < size {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to communicate with the image streamer",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CollectFlags {
    pub shared: bool,
    pub nofree: bool,
    pub happened: bool,
}

use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;

pub trait ImageCollector {
    type Item: Message + Default;
    type PrivData: Default;

    fn fd_type() -> CrFdType;
    fn flags() -> CollectFlags {
        CollectFlags::default()
    }
    fn collect(priv_data: &mut Self::PrivData, msg: Self::Item, img: &mut CrImg) -> io::Result<()>;
}

pub fn collect_image<C: ImageCollector>(dfd: RawFd) -> io::Result<bool> {
    let mut img = open_image(dfd, C::fd_type(), "")?;
    let flags = C::flags();

    log::info!(
        "Collecting {:?} (flags {:?})",
        C::fd_type(),
        flags
    );

    let mut happened = false;

    loop {
        let mut priv_data = C::PrivData::default();

        match pb_read_one_eof::<C::Item>(&mut img)? {
            Some(msg) => {
                happened = true;
                C::collect(&mut priv_data, msg, &mut img)?;
            }
            None => break,
        }
    }

    close_image(&mut img);
    log::debug!(" `- ... done");

    Ok(happened)
}
