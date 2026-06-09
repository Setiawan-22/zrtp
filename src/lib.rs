pub mod crypto;
pub mod fec;
pub mod tcp;
pub mod udp;
pub mod input;
pub mod payload;

pub struct FrameBuffer {
    pub shards: Vec<Option<Vec<u8>>>,
    pub received_count: usize,
}

pub struct SessionState {
    pub key: [u8; 32],
    pub timeout_frames: u32,
    pub highest_tcp_nonce: u64,
    pub highest_udp_frame_id: u32,
    pub udp_frame_buffers: std::collections::BTreeMap<u32, FrameBuffer>,
}
