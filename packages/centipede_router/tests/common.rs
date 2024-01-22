use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

/// A dummy cipher for testing.
pub fn dummy_cipher() -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&[0; 32].into())
}
