#ifndef AeronyxCrypto_h
#define AeronyxCrypto_h

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// ByteBuffer struct for passing data between Rust and Swift
typedef struct {
    uint8_t* data;
    size_t len;
    size_t capacity;
} ByteBuffer;

// Declarations for Rust functions
int32_t aeronyx_free_buffer(ByteBuffer* buffer);

int32_t aeronyx_ed25519_private_to_x25519(
    const uint8_t* ed25519_private,
    size_t ed25519_private_len,
    ByteBuffer** out_buffer);

int32_t aeronyx_ed25519_public_to_x25519(
    const uint8_t* ed25519_public,
    size_t ed25519_public_len,
    ByteBuffer** out_buffer);

int32_t aeronyx_sign_ed25519(
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* message,
    size_t message_len,
    ByteBuffer** out_buffer);

int32_t aeronyx_verify_ed25519(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len);

int32_t aeronyx_encrypt_chacha20poly1305(
    const uint8_t* data,
    size_t data_len,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    ByteBuffer** out_ciphertext,
    ByteBuffer** out_nonce);

int32_t aeronyx_decrypt_chacha20poly1305(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* nonce,
    size_t nonce_len,
    ByteBuffer** out_buffer);

int32_t aeronyx_derive_key(
    const uint8_t* key_material,
    size_t key_material_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    size_t output_length,
    ByteBuffer** out_buffer);

#endif /* AeronyxCrypto_h */
