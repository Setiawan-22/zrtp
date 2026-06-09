use std::io;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use futures::{StreamExt, SinkExt};
use bytes::Bytes;
use crate::payload::{NetworkPacket, PacketHeader, PacketType};
use crate::input::InputCommand;
use crate::fec::FecProfile;
use crate::crypto::ZrtpCrypto;
use crate::SessionState;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};

pub async fn start_tcp_server(
    port: u16, 
    input_tx: mpsc::Sender<InputCommand>,
    session_keys: Arc<Mutex<HashMap<u64, SessionState>>>
) -> io::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("TCP Server mendengarkan di {}", addr);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Koneksi TCP baru dari: {}", addr);
        let input_tx_clone = input_tx.clone();
        let session_keys_clone = Arc::clone(&session_keys);

        tokio::spawn(async move {
            let (read_half, write_half) = socket.into_split();
            let mut framed_read = FramedRead::new(read_half, LengthDelimitedCodec::new());
            let mut framed_write = FramedWrite::new(write_half, LengthDelimitedCodec::new());
            
            let mut active_session_id: Option<u64> = None;

            while let Some(frame_result) = framed_read.next().await {
                match frame_result {
                    Ok(bytes_mut) => {
                        // ANTI-CRASH: Menggunakan match untuk menghindari panic pada input ngawur
                        match bincode::deserialize::<NetworkPacket>(&bytes_mut) {
                            Ok(network_packet) => {
                                match network_packet {
                                    NetworkPacket::HandshakeInitiate { requested_fec, timeout_tolerance_frames, client_public_key } => {
                                        println!("[TCP] Memulai Handshake X25519 dengan Klien: {}", addr);
                                        
                                        match ZrtpCrypto::generate_x25519_keypair() {
                                            Ok((host_priv, host_pub)) => {
                                                match ZrtpCrypto::derive_shared_secret(host_priv, &client_public_key) {
                                                    Ok(shared_secret) => {
                                                        // SESSION DINAMIS: Gunakan rand untuk ID unik
                                                        let session_id = rand::random::<u64>();
                                                        active_session_id = Some(session_id);
                                                        
                                                        session_keys_clone.lock().unwrap().insert(session_id, SessionState {
                                                            key: shared_secret,
                                                            timeout_frames: timeout_tolerance_frames,
                                                            highest_tcp_nonce: 0,
                                                            highest_udp_frame_id: 0,
                                                            udp_frame_buffers: std::collections::BTreeMap::new(),
                                                        });

                                                        let assigned_fec = match requested_fec.as_str() {
                                                            "TheFortress" => FecProfile::TheFortress,
                                                            "TheSurvivalist" => FecProfile::TheSurvivalist,
                                                            _ => FecProfile::TheDailyDriver,
                                                        };

                                                        let response = NetworkPacket::HandshakeAccept {
                                                            session_id,
                                                            assigned_fec,
                                                            host_public_key: host_pub,
                                                        };

                                                        if let Ok(response_bytes) = bincode::serialize(&response) {
                                                            if let Err(e) = framed_write.send(Bytes::from(response_bytes)).await {
                                                                eprintln!("[TCP] Gagal membalas Handshake: {}", e);
                                                            } else {
                                                                println!("[TCP] Sesi Dinamis Terbuat! Sesi: {} (Toleransi Timeout: {} frame)", session_id, timeout_tolerance_frames);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => eprintln!("[TCP] Error DH Shared Secret: {}", e),
                                                }
                                            }
                                            Err(e) => eprintln!("[TCP] Gagal generate keypair: {}", e),
                                        }
                                    }
                                    NetworkPacket::EncryptedPayload { session_id, nonce, ciphertext } => {
                                        // ANTI-REPLAY ATTACK: Mengurai nonce jadi u64
                                        let mut nonce_bytes = [0u8; 8];
                                        nonce_bytes.copy_from_slice(&nonce[0..8]);
                                        let nonce_u64 = u64::from_le_bytes(nonce_bytes);

                                        let mut state_opt = None;
                                        {
                                            let mut map = session_keys_clone.lock().unwrap();
                                            if let Some(state) = map.get_mut(&session_id) {
                                                if nonce_u64 <= state.highest_tcp_nonce && state.highest_tcp_nonce > 0 {
                                                    eprintln!("[SECURITY] 🚨 REPLAY ATTACK DIBLOKIR dari {}! Klien menggunakan Nonce Usang: {}", addr, nonce_u64);
                                                } else {
                                                    state.highest_tcp_nonce = nonce_u64;
                                                    state_opt = Some(state.key.clone());
                                                }
                                            }
                                        }
                                        
                                        if let Some(key) = state_opt {
                                            match ZrtpCrypto::decrypt_payload(&key, nonce, ciphertext) {
                                                Ok(plaintext) => {
                                                    if let Ok(packet) = bincode::deserialize::<PacketHeader>(&plaintext) {
                                                        match packet.packet_type {
                                                            PacketType::InputEvent { button_code, is_pressed } => {
                                                                let cmd = InputCommand { button_code, is_pressed };
                                                                let _ = input_tx_clone.send(cmd).await;
                                                            }
                                                            PacketType::Ping { timestamp, .. } => {
                                                                println!("[TCP] 💓 Menerima Heartbeat PING (TS: {}) dari {}", timestamp, addr);
                                                                let pong_header = PacketHeader {
                                                                    version: 1,
                                                                    packet_type: PacketType::Pong { timestamp },
                                                                    session_id,
                                                                    sequence_number: packet.sequence_number,
                                                                    timestamp: 0,
                                                                };
                                                                
                                                                let mut pong_nonce = [0u8; 12];
                                                                // Server menggunakan bit marker 255 untuk jalur balik (Pong) agar terhindar dari tabrakan nonce Klien
                                                                pong_nonce[0..8].copy_from_slice(&nonce_u64.to_le_bytes());
                                                                pong_nonce[11] = 255; 

                                                                if let Ok(ph_bytes) = bincode::serialize(&pong_header) {
                                                                    if let Ok(ct) = ZrtpCrypto::encrypt_payload(&key, pong_nonce, ph_bytes) {
                                                                        let pkt = NetworkPacket::EncryptedPayload { session_id, nonce: pong_nonce, ciphertext: ct };
                                                                        if let Ok(b) = bincode::serialize(&pkt) {
                                                                            let _ = framed_write.send(Bytes::from(b)).await;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            _ => {
                                                                println!("[TCP] Menerima paket routing rahasia: {:?}", packet.packet_type);
                                                            }
                                                        }
                                                    } else {
                                                        eprintln!("[WARN] Paket terenkripsi berhasil dibuka tapi format dalamnya cacat (Garbage Bincode).");
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("[TCP] [BLOCKED] Enkripsi Gagal! Penyusup terdeteksi: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        eprintln!("[TCP] Menerima tipe jaringan yang salah!");
                                    }
                                }
                            }
                            Err(_) => {
                                eprintln!("[SECURITY] 🛡️ [ANTI-CRASH] Menerima data sampah (Garbage Bytes) tak beraturan dari {}. Paket diabaikan secara anggun.", addr);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[TCP] Error membaca stream dari {}: {}", addr, e);
                        break;
                    }
                }
            }

            // TCP SESSION GARBAGE COLLECTOR
            if let Some(id) = active_session_id {
                session_keys_clone.lock().unwrap().remove(&id);
                println!("[TCP-GC] Klien terputus. Kunci Sesi {} dihapus secara otomatis dari memori!", id);
            }
            println!("Koneksi TCP dari {} terputus.", addr);
        });
    }
}
