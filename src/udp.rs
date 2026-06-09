use std::io;
use tokio::net::UdpSocket;
use crate::payload::{NetworkPacket, PacketHeader, PacketType};
use crate::fec::{FecEngine, FecProfile};
use crate::crypto::ZrtpCrypto;
use crate::SessionState;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};



pub async fn start_udp_server(
    port: u16,
    session_keys: Arc<Mutex<HashMap<u64, SessionState>>>,
    tx: Option<tokio::sync::broadcast::Sender<Vec<u8>>>
) -> io::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    println!("UDP Socket mendengarkan di {}", addr);

    let mut fec_engine = match FecEngine::new(FecProfile::TheDailyDriver) {
        Ok(engine) => engine,
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Gagal inisialisasi FEC Engine")),
    };

    // UDP GARBAGE COLLECTOR TINGKAT TINGGI (Menggunakan BTreeMap di dalam SessionState)

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _src_addr)) => {
                let data = &buf[..len];
                
                // ANTI-CRASH: Tidak menggunakan unwrap
                match bincode::deserialize::<NetworkPacket>(data) {
                    Ok(network_packet) => {
                        if let NetworkPacket::EncryptedPayload { session_id, nonce, ciphertext } = network_packet {
                            
                            let session_opt = {
                                let map = session_keys.lock().unwrap();
                                map.get(&session_id).map(|s| (s.key.clone(), s.timeout_frames))
                            };
                            
                            if let Some((key, timeout_frames)) = session_opt {
                                match ZrtpCrypto::decrypt_payload(&key, nonce, ciphertext) {
                                    Ok(plaintext) => {
                                        // ANTI-CRASH: Tidak menggunakan unwrap
                                        if let Ok(packet) = bincode::deserialize::<PacketHeader>(&plaintext) {
                                            if let PacketType::FecShard { frame_id, shard_index, data_shards, parity_shards, original_len, data: shard_data, .. } = packet.packet_type {
                                                
                                                let total_shards_dynamic = (data_shards + parity_shards) as usize;
                                                let mut ready_shards = None;
                                                
                                                {
                                                    let mut map = session_keys.lock().unwrap();
                                                    if let Some(state) = map.get_mut(&session_id) {
                                                        if frame_id > state.highest_udp_frame_id {
                                                            state.highest_udp_frame_id = frame_id;
                                                            let cutoff = state.highest_udp_frame_id.saturating_sub(timeout_frames);
                                                            
                                                            let initial_count = state.udp_frame_buffers.len();
                                                            let active_frames = state.udp_frame_buffers.split_off(&cutoff);
                                                            
                                                            let removed = initial_count - active_frames.len();
                                                            if removed > 0 {
                                                                println!("[UDP-GC] Sesi {}: Membuang {} Frame Basi (Gap melebihi {} frame). RAM dibersihkan!", session_id, removed, timeout_frames);
                                                            }
                                                            
                                                            state.udp_frame_buffers = active_frames;
                                                        } 
                                                        else if frame_id < state.highest_udp_frame_id.saturating_sub(timeout_frames) {
                                                            // Replay paket lama / paket super nyasar
                                                            continue;
                                                        }

                                                        let buffer = state.udp_frame_buffers.entry(frame_id).or_insert_with(|| crate::FrameBuffer {
                                                            shards: vec![None; total_shards_dynamic],
                                                            received_count: 0,
                                                        });

                                                        if (shard_index as usize) < total_shards_dynamic && buffer.shards[shard_index as usize].is_none() {
                                                            buffer.shards[shard_index as usize] = Some(shard_data);
                                                            buffer.received_count += 1;
                                                            
                                                            if buffer.received_count == data_shards as usize {
                                                                if let Some(ready_buffer) = state.udp_frame_buffers.remove(&frame_id) {
                                                                    ready_shards = Some((ready_buffer.shards, data_shards, parity_shards));
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                // Eksekusi decode setelah melepaskan lock session_keys
                                                if let Some((shards_to_decode, d_shards, p_shards)) = ready_shards {
                                                    match fec_engine.decode(shards_to_decode, d_shards as usize, p_shards as usize, original_len as usize) {
                                                        Ok(reconstructed_frame) => {
                                                            println!("[UDP] [RAHASIA] Frame #{} berukuran {} bytes utuh direkonstruksi secara dinamis!", frame_id, original_len);
                                                            // MENGIRIM FRAME KE WEB DASHBOARD (JIKA ADA)
                                                            if let Some(ref broadcaster) = tx {
                                                                let _ = broadcaster.send(reconstructed_frame);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!("[UDP] Gagal rekonstruksi frame #{}: {}", frame_id, e);
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            eprintln!("[WARN] Paket dekripsi berhasil tapi format header cacat!");
                                        }
                                    }
                                    Err(_) => {
                                        // Jangan di log tiap kali ada corrupt UDP untuk mencegah DDoS log spamming.
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Anti-Crash: Abaikan secara senyap UDP Garbage bytes.
                    }
                }
            }
            Err(e) => {
                eprintln!("[UDP] Error fatal socket: {}", e);
            }
        }
    }
}
