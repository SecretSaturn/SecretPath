use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encrypt_payload(
    gateway_public_key: &[u8],
    user_private_key: &[u8],
    plaintext: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let user_private_key = SecretKey::from_slice(user_private_key).unwrap();
    let gateway_public_key = PublicKey::from_slice(gateway_public_key).unwrap();
    let shared_key = SharedSecret::new(&gateway_public_key, &user_private_key);

    let shared_key = Key::from_slice(shared_key.as_ref()); // 32-bytes
    let cipher = ChaCha20Poly1305::new(shared_key);

    let nonce = Nonce::from_slice(nonce); // 12-bytes; unique per message

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    return ciphertext;
}
