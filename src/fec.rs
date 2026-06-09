#![allow(dead_code)]

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FecProfile {
    /// 20 Data, 2 Parity. Untuk LAN / Datacenter (Overhead ~10%)
    TheFortress,
    /// 10 Data, 3 Parity. Untuk Internet Publik / Cloud Gaming (Overhead ~30%)
    TheDailyDriver,
    /// 4 Data, 2 Parity. Untuk kondisi ekstrim / Drone / IoT (Overhead ~50%)
    TheSurvivalist,
    /// Custom rasio
    #[allow(dead_code)]
    Custom(usize, usize),
}

impl FecProfile {
    pub fn get_ratio(&self) -> (usize, usize) {
        match self {
            FecProfile::TheFortress => (20, 2),
            FecProfile::TheDailyDriver => (10, 3),
            FecProfile::TheSurvivalist => (4, 2),
            FecProfile::Custom(data, parity) => (*data, *parity),
        }
    }
}

use std::collections::HashMap;

const MAX_SHARD_SIZE: usize = 1200;

pub struct FecEngine {
    cache: HashMap<(usize, usize), ReedSolomon>,
    pub active_profile: FecProfile,
}

impl FecEngine {
    pub fn new(profile: FecProfile) -> Result<Self, &'static str> {
        Ok(Self {
            cache: HashMap::new(),
            active_profile: profile,
        })
    }

    fn get_or_create_rs(&mut self, data_shards: usize, parity_shards: usize) -> Result<&ReedSolomon, &'static str> {
        if !self.cache.contains_key(&(data_shards, parity_shards)) {
            let rs = ReedSolomon::new(data_shards, parity_shards)
                .map_err(|_| "Gagal inisialisasi ReedSolomon (jumlah shard terlalu besar?)")?;
            self.cache.insert((data_shards, parity_shards), rs);
        }
        Ok(self.cache.get(&(data_shards, parity_shards)).unwrap())
    }

    /// Memecah payload mentah menjadi sekumpulan shard dengan batas ukuran maksimum (MTU Safe)
    /// Mengembalikan: (List Shards, Jumlah Data Shard, Jumlah Parity Shard)
    pub fn encode(&mut self, payload: &[u8]) -> Result<(Vec<Vec<u8>>, u16, u16), &'static str> {
        let payload_len = payload.len();
        if payload_len == 0 {
            return Err("Payload kosong");
        }
        
        // Kalkulasi dinamis berdasarkan limitasi MTU jaringan
        let data_shards = (payload_len + MAX_SHARD_SIZE - 1) / MAX_SHARD_SIZE;
        let (prof_data, prof_parity) = self.active_profile.get_ratio();
        
        let parity_shards = ((data_shards * prof_parity) as f32 / prof_data as f32).ceil() as usize;
        let parity_shards = std::cmp::max(1, parity_shards);
        
        let shard_size = (payload_len + data_shards - 1) / data_shards;
        let mut shards = vec![vec![0u8; shard_size]; data_shards + parity_shards];

        for (i, chunk) in payload.chunks(shard_size).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }

        let rs = self.get_or_create_rs(data_shards, parity_shards)?;
        rs.encode(&mut shards).map_err(|_| "Gagal melakukan encode RS")?;

        Ok((shards, data_shards as u16, parity_shards as u16))
    }

    /// Merekonstruksi payload dari dimensi dinamis
    pub fn decode(&mut self, mut shards: Vec<Option<Vec<u8>>>, data_shards: usize, parity_shards: usize, original_len: usize) -> Result<Vec<u8>, &'static str> {
        if shards.len() != data_shards + parity_shards {
            return Err("Jumlah shard tidak sesuai dengan konfigurasi dinamis FEC");
        }

        let rs = self.get_or_create_rs(data_shards, parity_shards)?;
        rs.reconstruct(&mut shards).map_err(|_| "Gagal rekonstruksi, terlalu banyak packet loss!")?;

        let shard_len = shards.iter().find_map(|s| s.as_ref().map(|v| v.len())).unwrap_or(0);
        let mut payload = Vec::with_capacity(data_shards * shard_len);
        
        for i in 0..data_shards {
            if let Some(ref shard) = shards[i] {
                payload.extend_from_slice(shard);
            }
        }
        
        payload.truncate(original_len);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_daily_driver_recovery() {
        let mut engine = FecEngine::new(FecProfile::TheDailyDriver).unwrap();
        let payload = b"Hello ZRTP Hybrid Protocol! Ini adalah pesan rahasia yang sangat panjang untuk menguji padding dan pemecahan data menjadi beberapa shard dinamis.".to_vec();
        
        let (encoded, data_shards, parity_shards) = engine.encode(&payload).unwrap();
        
        let mut received = Vec::new();
        for (i, shard) in encoded.into_iter().enumerate() {
            // Drop some shards dynamically
            if i % 3 == 0 { 
                received.push(None);
            } else {
                received.push(Some(shard));
            }
        }

        let decoded = engine.decode(received, data_shards as usize, parity_shards as usize, payload.len()).expect("Harus berhasil decode!");
        assert_eq!(payload, decoded);
    }
}
