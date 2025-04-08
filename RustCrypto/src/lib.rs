//lib.rs

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use ed25519_dalek::Signer;  // 添加这个Trait
use ed25519_dalek::Verifier; // 添加这个Trait
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;  // 添加这个Trait
use sha2::{Digest, Sha256, Sha512};
use std::slice;
use std::ptr;
use std::os::raw::c_int;  // 只保留需要的类型

// Error codes
const AERONYX_SUCCESS: c_int = 0;
const AERONYX_ERROR_NULL_POINTER: c_int = -1;
const AERONYX_ERROR_INVALID_LENGTH: c_int = -2;
const AERONYX_ERROR_CONVERSION_FAILED: c_int = -3;
const AERONYX_ERROR_CRYPTO_FAILED: c_int = -4;
const AERONYX_ERROR_MEMORY: c_int = -5;

// Byte buffer for passing data between Rust and Swift
#[repr(C)]
pub struct ByteBuffer {
    data: *mut u8,
    len: usize,
    capacity: usize,
}

impl ByteBuffer {
    pub fn new() -> ByteBuffer {
        ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }
    
    pub fn from_vec(vec: Vec<u8>) -> ByteBuffer {
        let mut vec = vec;
        let buf = ByteBuffer {
            data: vec.as_mut_ptr(),
            len: vec.len(),
            capacity: vec.capacity(),
        };
        std::mem::forget(vec);
        buf
    }
    
    pub unsafe fn destroy(&mut self) {
        if !self.data.is_null() {
            let _ = Vec::from_raw_parts(self.data, self.len, self.capacity);
            self.data = ptr::null_mut();
            self.len = 0;
            self.capacity = 0;
        }
    }
}

// Free a ByteBuffer from C
#[no_mangle]
pub extern "C" fn aeronyx_free_buffer(buffer: *mut ByteBuffer) -> c_int {
    if buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    unsafe {
        (*buffer).destroy();
        Box::from_raw(buffer);
    }
    
    AERONYX_SUCCESS
}

// Ed25519 private key to X25519 conversion
#[no_mangle]
pub extern "C" fn aeronyx_ed25519_private_to_x25519(
    ed25519_private: *const u8,
    ed25519_private_len: usize,
    out_buffer: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if ed25519_private.is_null() || out_buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if ed25519_private_len != 32 && ed25519_private_len != 64 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let private_key_bytes = unsafe { slice::from_raw_parts(ed25519_private, ed25519_private_len) };
    
    // Extract the first 32 bytes if we're given a 64-byte keypair
    let actual_private_key = if ed25519_private_len == 64 {
        &private_key_bytes[0..32]
    } else {
        private_key_bytes
    };
    
    // Hash the private key with SHA-512
    let mut hash = Sha512::new();
    hash.update(actual_private_key);
    let hash_result = hash.finalize();
    
    // Extract lower 32 bytes
    let mut x25519_private = [0u8; 32];
    x25519_private.copy_from_slice(&hash_result[0..32]);
    
    // Apply bit clamping as per RFC 7748
    x25519_private[0] &= 248;  // Clear bits 0, 1, 2
    x25519_private[31] &= 127; // Clear bit 255
    x25519_private[31] |= 64;  // Set bit 254
    
    // Create the result buffer
    let buffer = Box::new(ByteBuffer::from_vec(x25519_private.to_vec()));
    unsafe {
        *out_buffer = Box::into_raw(buffer);
    }
    
    AERONYX_SUCCESS
}

// Ed25519 public key to X25519 conversion
#[no_mangle]
pub extern "C" fn aeronyx_ed25519_public_to_x25519(
    ed25519_public: *const u8,
    ed25519_public_len: usize,
    out_buffer: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if ed25519_public.is_null() || out_buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if ed25519_public_len != 32 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let public_key_bytes = unsafe { slice::from_raw_parts(ed25519_public, ed25519_public_len) };
    
    // Parse the Edwards point
    let compressed = CompressedEdwardsY::from_slice(public_key_bytes);
    let edwards_point = match compressed.decompress() {
        Some(point) => point,
        None => {
            return AERONYX_ERROR_CONVERSION_FAILED;
        }
    };
    
    // Convert to Montgomery form
    let montgomery_bytes = edwards_point.to_montgomery().to_bytes();
    
    // Create the result buffer
    let buffer = Box::new(ByteBuffer::from_vec(montgomery_bytes.to_vec()));
    unsafe {
        *out_buffer = Box::into_raw(buffer);
    }
    
    AERONYX_SUCCESS
}

// Sign data with Ed25519 key
#[no_mangle]
pub extern "C" fn aeronyx_sign_ed25519(
    private_key: *const u8,
    private_key_len: usize,
    message: *const u8,
    message_len: usize,
    out_buffer: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if private_key.is_null() || message.is_null() || out_buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if (private_key_len != 32 && private_key_len != 64) || message_len == 0 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let private_key_bytes = unsafe { slice::from_raw_parts(private_key, private_key_len) };
    let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
    
    // Create keypair from private key
    let signature_result = if private_key_len == 32 {
        // Just secret key
        match SecretKey::from_bytes(private_key_bytes) {
            Ok(secret) => {
                let public = PublicKey::from(&secret);
                let keypair = Keypair { secret, public };
                Ok(keypair.sign(message_bytes).to_bytes().to_vec())
            }
            Err(_) => Err(AERONYX_ERROR_CRYPTO_FAILED)
        }
    } else {
        // Full keypair (64 bytes)
        match Keypair::from_bytes(private_key_bytes) {
            Ok(keypair) => Ok(keypair.sign(message_bytes).to_bytes().to_vec()),
            Err(_) => Err(AERONYX_ERROR_CRYPTO_FAILED)
        }
    };
    
    match signature_result {
        Ok(signature) => {
            let buffer = Box::new(ByteBuffer::from_vec(signature));
            unsafe {
                *out_buffer = Box::into_raw(buffer);
            }
            AERONYX_SUCCESS
        },
        Err(err) => err
    }
}

// Verify Ed25519 signature
#[no_mangle]
pub extern "C" fn aeronyx_verify_ed25519(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    // Check parameters
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if public_key_len != 32 || signature_len != 64 || message_len == 0 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let public_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
    let signature_bytes = unsafe { slice::from_raw_parts(signature, signature_len) };
    
    match PublicKey::from_bytes(public_bytes) {
        Ok(public) => {
            match Signature::from_bytes(signature_bytes) {
                Ok(sig) => {
                    match public.verify(message_bytes, &sig) {
                        Ok(_) => AERONYX_SUCCESS,
                        Err(_) => AERONYX_ERROR_CRYPTO_FAILED
                    }
                }
                Err(_) => AERONYX_ERROR_CRYPTO_FAILED
            }
        }
        Err(_) => AERONYX_ERROR_CRYPTO_FAILED
    }
}

// Encrypt using ChaCha20-Poly1305
#[no_mangle]
pub extern "C" fn aeronyx_encrypt_chacha20poly1305(
    data: *const u8,
    data_len: usize,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    out_ciphertext: *mut *mut ByteBuffer,
    out_nonce: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if data.is_null() || key.is_null() || out_ciphertext.is_null() || out_nonce.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if key_len != 32 || data_len == 0 || (nonce != ptr::null() && nonce_len != 12) {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    
    // Create the cipher
    let cipher_key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    // Generate or use provided nonce
    let nonce_bytes = if nonce.is_null() {
        let mut random_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut random_nonce);
        random_nonce.to_vec()
    } else {
        unsafe { slice::from_raw_parts(nonce, nonce_len).to_vec() }
    };
    
    let nonce_obj = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    match cipher.encrypt(nonce_obj, data_bytes) {
        Ok(ciphertext) => {
            // Return ciphertext and nonce separately
            let ctext_buffer = Box::new(ByteBuffer::from_vec(ciphertext));
            let nonce_buffer = Box::new(ByteBuffer::from_vec(nonce_bytes));
            
            unsafe {
                *out_ciphertext = Box::into_raw(ctext_buffer);
                *out_nonce = Box::into_raw(nonce_buffer);
            }
            
            AERONYX_SUCCESS
        }
        Err(_) => AERONYX_ERROR_CRYPTO_FAILED
    }
}

// Decrypt using ChaCha20-Poly1305
#[no_mangle]
pub extern "C" fn aeronyx_decrypt_chacha20poly1305(
    ciphertext: *const u8,
    ciphertext_len: usize,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    out_buffer: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if ciphertext.is_null() || key.is_null() || nonce.is_null() || out_buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if key_len != 32 || nonce_len != 12 || ciphertext_len == 0 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let ciphertext_bytes = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_bytes = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    
    // Create the cipher
    let cipher_key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce_obj = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the data
    match cipher.decrypt(nonce_obj, ciphertext_bytes) {
        Ok(plaintext) => {
            let buffer = Box::new(ByteBuffer::from_vec(plaintext));
            unsafe {
                *out_buffer = Box::into_raw(buffer);
            }
            AERONYX_SUCCESS
        }
        Err(_) => AERONYX_ERROR_CRYPTO_FAILED
    }
}

// Derive key using HKDF
#[no_mangle]
pub extern "C" fn aeronyx_derive_key(
    key_material: *const u8,
    key_material_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    output_length: usize,
    out_buffer: *mut *mut ByteBuffer,
) -> c_int {
    // Check parameters
    if key_material.is_null() || out_buffer.is_null() {
        return AERONYX_ERROR_NULL_POINTER;
    }
    
    if key_material_len == 0 || output_length == 0 {
        return AERONYX_ERROR_INVALID_LENGTH;
    }
    
    let key_material_bytes = unsafe { slice::from_raw_parts(key_material, key_material_len) };
    let salt_bytes = if salt.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(salt, salt_len) }
    };
    let info_bytes = if info.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(info, info_len) }
    };
    
    // Create HKDF
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), key_material_bytes);
    let mut output = vec![0u8; output_length];
    
    match hk.expand(info_bytes, &mut output) {
        Ok(_) => {
            let buffer = Box::new(ByteBuffer::from_vec(output));
            unsafe {
                *out_buffer = Box::into_raw(buffer);
            }
            AERONYX_SUCCESS
        }
        Err(_) => AERONYX_ERROR_CRYPTO_FAILED
    }
}
