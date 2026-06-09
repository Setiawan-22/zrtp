use serde::{Deserialize, Serialize};
use crate::fec::FecProfile;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkPacket {
    // 1. Fase Jabat Tangan (Cleartext / Tidak dienkripsi)
    HandshakeInitiate { 
        requested_fec: String, 
        timeout_tolerance_frames: u32,
        client_public_key: Vec<u8> 
    },
    HandshakeAccept { 
        session_id: u64, 
        assigned_fec: FecProfile, 
        host_public_key: Vec<u8> 
    },
    
    // 2. Fase Operasional (Terenkripsi)
    EncryptedPayload { 
        session_id: u64, 
        nonce: [u8; 12], 
        ciphertext: Vec<u8> // Bincode terenkripsi dari PacketHeader
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PacketType {
    // Sinyal Manajemen Koneksi
    Ping { timestamp: u64, reported_loss: f32 },
    Pong { timestamp: u64 },
    
    // Jalur TCP
    Chat { sender: String, message: String },
    InputEvent { button_code: u16, is_pressed: bool },
    
    // Jalur UDP
    FecShard { 
        frame_id: u32, 
        shard_index: u16, 
        data_shards: u16,
        parity_shards: u16,
        original_len: u32, 
        data: Vec<u8> 
    },
    AudioChunk { data: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub session_id: u64,
    pub sequence_number: u32,
    pub timestamp: u64,
}
