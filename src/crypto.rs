use ring::{
    aead::{self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey},
    agreement,
    rand::SystemRandom,
};

pub type CryptoError = &'static str;

// Implementasi NonceSequence khusus (Wajib untuk ring aead)
pub struct ZrtpNonceSequence {
    nonce: [u8; 12],
}

impl ZrtpNonceSequence {
    pub fn new(nonce: [u8; 12]) -> Self {
        Self { nonce }
    }
}

impl NonceSequence for ZrtpNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Nonce::try_assume_unique_for_key(&self.nonce)
    }
}

pub struct ZrtpCrypto;

impl ZrtpCrypto {
    /// 1. X25519: Generate sepasang kunci (Private & Public Key)
    pub fn generate_x25519_keypair() -> Result<(agreement::EphemeralPrivateKey, Vec<u8>), CryptoError> {
        let rng = SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| "Gagal generate private key")?;
        
        let public_key = private_key.compute_public_key()
            .map_err(|_| "Gagal compute public key")?
            .as_ref().to_vec();

        Ok((private_key, public_key))
    }

    /// 2. X25519: Campur Kunci Publik Lawan + Kunci Privat Sendiri = Shared Secret!
    pub fn derive_shared_secret(
        my_private_key: agreement::EphemeralPrivateKey,
        peer_public_key: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        let peer_public_key_unparsed = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);
        
        agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key_unparsed,
            |key_material: &[u8]| {
                let mut shared_secret = [0u8; 32];
                let len = std::cmp::min(key_material.len(), 32);
                shared_secret[..len].copy_from_slice(&key_material[..len]);
                shared_secret
            },
        ).map_err(|_| "Gagal melakukan kalkulasi kunci Diffie-Hellman")
    }

    /// 3. ChaCha20-Poly1305: Enkripsi Data
    #[allow(dead_code)]
    pub fn encrypt_payload(
        key: &[u8; 32],
        nonce: [u8; 12],
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|_| "Gagal inisialisasi kunci enkripsi")?;
        
        let mut sealing_key = SealingKey::new(unbound_key, ZrtpNonceSequence::new(nonce));
        
        sealing_key.seal_in_place_append_tag(
            Aad::empty(),
            &mut data,
        ).map_err(|_| "Gagal melakukan enkripsi ChaCha20")?;

        Ok(data)
    }

    /// 4. ChaCha20-Poly1305: Dekripsi Data
    pub fn decrypt_payload(
        key: &[u8; 32],
        nonce: [u8; 12],
        mut ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|_| "Gagal inisialisasi kunci dekripsi")?;
            
        let mut opening_key = OpeningKey::new(unbound_key, ZrtpNonceSequence::new(nonce));
        
        let plaintext_slice = opening_key.open_in_place(
            Aad::empty(),
            &mut ciphertext,
        ).map_err(|_| "Data corrupt atau Kunci/Nonce salah (PENYADAPAN TERDETEKSI)")?;

        let plaintext_len = plaintext_slice.len();
        ciphertext.truncate(plaintext_len);
        
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_chacha20_handshake_flow() {
        // Simulasi Client dan Server membuat kunci sesaat
        let (client_priv, client_pub) = ZrtpCrypto::generate_x25519_keypair().unwrap();
        let (server_priv, server_pub) = ZrtpCrypto::generate_x25519_keypair().unwrap();

        // Mereka bertukar public key melalui internet, lalu kalkulasi shared secret secara gaib!
        let client_shared_secret = ZrtpCrypto::derive_shared_secret(client_priv, &server_pub).unwrap();
        let server_shared_secret = ZrtpCrypto::derive_shared_secret(server_priv, &client_pub).unwrap();

        // Rahasianya harus persis sama tanpa pernah dikirim via internet
        assert_eq!(client_shared_secret, server_shared_secret);

        // Client mengirim video frame terenkripsi
        let nonce = [9u8; 12];
        let frame = b"Ini adalah rahasia negara".to_vec();
        
        let ciphertext = ZrtpCrypto::encrypt_payload(&client_shared_secret, nonce, frame.clone()).unwrap();
        
        // Server menerima dan membukanya
        let decrypted = ZrtpCrypto::decrypt_payload(&server_shared_secret, nonce, ciphertext).unwrap();
        assert_eq!(decrypted, frame);
    }
}
