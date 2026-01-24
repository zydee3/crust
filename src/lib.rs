pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

pub mod compel;
pub mod criu;
