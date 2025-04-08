import Foundation
import CryptoKit
import os.log
import AeronyxCryptoModule

// --- Error Enum ---
enum AeronyxCryptoError: Error, LocalizedError {
    case rustError(code: Int32, message: String = "See Rust logs for details")
    case nullPointerReturned
    case invalidInputLength(String)
    case conversionFailed(String) // 添加关联值
    case signFailed
    case verifyFailed
    case ecdhFailed
    case encryptionFailed
    case decryptionFailed
    case hkdfFailed
    case keypairNotFound
    case invalidKeyFormat
    
    // 添加内部错误类型，替代原来未定义的rustInternalError
    static func rustInternalError(_ message: String) -> AeronyxCryptoError {
        return .rustError(code: -999, message: message)
    }

    // Helper to create error from Rust return code
    static func from(code: Int32, operation: String) -> AeronyxCryptoError? {
        guard code != 0 else { return nil } // 0 means success, no error

        let message = "Rust operation '\(operation)' failed with code \(code)."
        switch code {
        case -1: return .rustError(code: code, message: "\(message) Likely null pointer input.")
        case -2: return .invalidInputLength("\(message) Invalid input length.")
        case -3: return .conversionFailed("\(message) Key conversion failed.")
        case -4: return .signFailed
        case -8: return .decryptionFailed
        default: return .rustError(code: code, message: message)
        }
    }

    var errorDescription: String? {
        switch self {
        case .rustError(let code, let message): return "Rust Error (code \(code)): \(message)"
        case .nullPointerReturned: return "Rust FFI returned a null pointer unexpectedly."
        case .invalidInputLength(let details): return "Invalid Input Length: \(details)"
        case .conversionFailed(let details): return "Key Conversion Failed: \(details)" // 更新以使用关联值
        case .signFailed: return "Signing Operation Failed"
        case .verifyFailed: return "Verification Failed"
        case .ecdhFailed: return "ECDH Key Agreement Failed"
        case .encryptionFailed: return "Encryption Failed"
        case .decryptionFailed: return "Decryption or Authentication Failed"
        case .hkdfFailed: return "HKDF Key Derivation Failed"
        case .keypairNotFound: return "Keypair not found in Keychain"
        case .invalidKeyFormat: return "Invalid key format during load/conversion"
        }
    }
}

// --- Swift Wrapper ---
class AeronyxCrypto {
    private static let log = OSLog(subsystem: "com.aeronyx.AeroNyx.PacketTunnel", category: "Crypto")

    // Helper function to process the result buffer pointer returned via out-parameter
    private static func processOutParamBuffer(_ bufferPtr: UnsafeMutablePointer<ByteBuffer>?, freeFunc: (UnsafeMutablePointer<ByteBuffer>?) -> Int32, operationName: String) throws -> Data {
        guard let ptr = bufferPtr else {
             os_log("Rust FFI call '%{public}s' succeeded but returned null buffer pointer.", log: log, type: .error, operationName)
             throw AeronyxCryptoError.nullPointerReturned
        }
        // IMPORTANT: Always free the buffer Rust allocated
        defer {
            // We assume freeFunc returns 0 on success, non-zero otherwise, but we don't usually check it here.
             _ = freeFunc(ptr)
        }

        let buffer = ptr.pointee
        // Check if Rust allocated a buffer but put nothing in it (shouldn't happen on success)
        guard buffer.len > 0 else {
             os_log("Rust FFI call '%{public}s' succeeded but returned empty buffer.", log: log, type: .error, operationName)
             throw AeronyxCryptoError.rustError(code: 0, message: "Rust returned empty buffer despite success code for \(operationName)")
        }
        guard let dataPtr = buffer.data else {
             os_log("Rust FFI call '%{public}s' succeeded but returned buffer with null data pointer.", log: log, type: .error, operationName)
             throw AeronyxCryptoError.nullPointerReturned
        }

        // Copy data from the buffer
        return Data(bytes: dataPtr, count: buffer.len)
    }

    // --- Public Static Methods ---

    static func ed25519PrivateToX25519(privateKey: Data) throws -> Data {
        // Assumes privateKey is 32 bytes for conversion
        guard privateKey.count == 32 else { throw AeronyxCryptoError.invalidInputLength("Ed25519 private key must be 32 bytes.")}

        var outputBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil // Prepare out-parameter

        let result: Int32 = try privateKey.withUnsafeBytes { keyPtr in
            guard let baseAddress = keyPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for private key.") }
            // Directly call the C function imported via module map
            return aeronyx_ed25519_private_to_x25519(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                privateKey.count,
                &outputBufferPtr // Pass pointer to our optional pointer
            )
        }

        // Check return code first
        if let error = AeronyxCryptoError.from(code: result, operation: "ed25519PrivateToX25519") {
            // Free buffer if Rust allocated one even on error (Rust FFI should clarify this contract)
            if let ptr = outputBufferPtr { aeronyx_free_buffer(ptr) }
            throw error
        }

        // Process the buffer returned via the out-parameter
        return try processOutParamBuffer(outputBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "ed25519PrivateToX25519")
    }

    static func ed25519PublicToX25519(publicKey: Data) throws -> Data {
         guard publicKey.count == 32 else { throw AeronyxCryptoError.invalidInputLength("Ed25519 public key must be 32 bytes.")}
         var outputBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil

         let result: Int32 = try publicKey.withUnsafeBytes { keyPtr in
             guard let baseAddress = keyPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for public key.") }
             return aeronyx_ed25519_public_to_x25519(
                 baseAddress.assumingMemoryBound(to: UInt8.self),
                 publicKey.count,
                 &outputBufferPtr
             )
         }

         if let error = AeronyxCryptoError.from(code: result, operation: "ed25519PublicToX25519") {
             if let ptr = outputBufferPtr { aeronyx_free_buffer(ptr) }
             throw error
         }
         return try processOutParamBuffer(outputBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "ed25519PublicToX25519")
    }

    static func signEd25519(privateKey: Data, message: Data) throws -> Data {
        guard privateKey.count == 32 || privateKey.count == 64 else {
            throw AeronyxCryptoError.invalidInputLength("Ed25519 private key must be 32 or 64 bytes.")
        }
        var outputBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil

        let result: Int32 = try privateKey.withUnsafeBytes { keyPtr in
            try message.withUnsafeBytes { msgPtr in
                guard let keyBaseAddress = keyPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for private key.") }
                guard let msgBaseAddress = msgPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for message.") }
                return aeronyx_sign_ed25519(
                    keyBaseAddress.assumingMemoryBound(to: UInt8.self),
                    privateKey.count,
                    msgBaseAddress.assumingMemoryBound(to: UInt8.self),
                    message.count,
                    &outputBufferPtr
                )
            }
        }

        if let error = AeronyxCryptoError.from(code: result, operation: "signEd25519") {
            if let ptr = outputBufferPtr { aeronyx_free_buffer(ptr) }
            throw error
        }

        // Signature is always 64 bytes
        let signatureData = try processOutParamBuffer(outputBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "signEd25519")
        guard signatureData.count == 64 else {
             // Freeing already happened in processOutParamBuffer if needed
             throw AeronyxCryptoError.rustInternalError("Signing returned unexpected length: \(signatureData.count)")
        }
        return signatureData
    }

    static func verifyEd25519(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard publicKey.count == 32 else { return false }
        guard signature.count == 64 else { return false }

        // This function returns 0 for SUCCESS in the C header, non-zero for failure.
        let result: Int32 = publicKey.withUnsafeBytes { pubKeyPtr in
            message.withUnsafeBytes { msgPtr in
                signature.withUnsafeBytes { sigPtr in
                    // Use guard let for baseAddress safety
                    guard let pubKeyBase = pubKeyPtr.baseAddress,
                          let msgBase = msgPtr.baseAddress,
                          let sigBase = sigPtr.baseAddress else {
                        os_log("Failed to get base address for verifyEd25519 inputs", log: log, type: .error)
                        return -1 // Indicate error
                    }
                    return aeronyx_verify_ed25519(
                        pubKeyBase.assumingMemoryBound(to: UInt8.self), publicKey.count,
                        msgBase.assumingMemoryBound(to: UInt8.self), message.count,
                        sigBase.assumingMemoryBound(to: UInt8.self), signature.count
                    )
                }
            }
        }
        // Return true if C function returned 0 (success)
        return result == 0
    }

    // Updated for the C API returning two output buffers
    static func encryptChaCha20Poly1305(data: Data, key: Data, nonce: Data? = nil) throws -> (ciphertextAndTag: Data, nonce: Data) {
         guard key.count == 32 else { throw AeronyxCryptoError.invalidInputLength("ChaChaPoly key must be 32 bytes.") }
         if let n = nonce, n.count != 12 { throw AeronyxCryptoError.invalidInputLength("Provided ChaChaPoly nonce must be 12 bytes.") }

         var ciphertextBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil
         var nonceOutBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil // For the *output* nonce

         let result: Int32 = try data.withUnsafeBytes { dataPtr in
             try key.withUnsafeBytes { keyPtr in
                 // Inner helper to handle optional input nonce pointer
                 func callEncrypt(nonceInPtr: UnsafePointer<UInt8>?, nonceInLen: Int) throws -> Int32 {
                      guard let dataBase = dataPtr.baseAddress, let keyBase = keyPtr.baseAddress else {
                           throw AeronyxCryptoError.invalidInputLength("Cannot get base address for data/key.")
                      }
                      return aeronyx_encrypt_chacha20poly1305(
                          dataBase.assumingMemoryBound(to: UInt8.self), data.count,
                          keyBase.assumingMemoryBound(to: UInt8.self), key.count,
                          nonceInPtr, nonceInLen, // Pass input nonce correctly
                          &ciphertextBufferPtr,   // Output ciphertext+tag buffer ptr
                          &nonceOutBufferPtr      // Output nonce buffer ptr
                      )
                  }

                 if let nonce = nonce {
                     // Pass the provided nonce
                     return try nonce.withUnsafeBytes { nonceInPtr -> Int32 in
                          guard let nonceBase = nonceInPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for nonce.") }
                          return try callEncrypt(nonceInPtr: nonceBase.assumingMemoryBound(to: UInt8.self), nonceInLen: nonce.count)
                     }
                 } else {
                     // Pass nil for input nonce, Rust will generate one
                     return try callEncrypt(nonceInPtr: nil, nonceInLen: 0)
                 }
             }
         }

         // Check return code first
         if let error = AeronyxCryptoError.from(code: result, operation: "encryptChaCha20Poly1305") {
             // Free any buffers Rust might have allocated even on error
             if let ptr = ciphertextBufferPtr { aeronyx_free_buffer(ptr) }
             if let ptr = nonceOutBufferPtr { aeronyx_free_buffer(ptr) }
             throw error
         }

         // Process output buffers
         let ciphertextData = try processOutParamBuffer(ciphertextBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "encryptChaCha20Poly1305_ciphertext")
         let nonceData = try processOutParamBuffer(nonceOutBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "encryptChaCha20Poly1305_nonce")

          // Basic validation
          guard nonceData.count == 12 else { throw AeronyxCryptoError.rustInternalError("Encryption returned invalid nonce length") }
          guard ciphertextData.count >= 16 else { throw AeronyxCryptoError.rustInternalError("Encryption returned invalid ciphertext length") }

         return (ciphertextData, nonceData)
    }

    static func decryptChaCha20Poly1305(ciphertext: Data, key: Data, nonce: Data) throws -> Data {
         guard key.count == 32 else { throw AeronyxCryptoError.invalidInputLength("ChaChaPoly key must be 32 bytes.") }
         guard nonce.count == 12 else { throw AeronyxCryptoError.invalidInputLength("ChaChaPoly nonce must be 12 bytes.") }
         guard ciphertext.count >= 16 else { throw AeronyxCryptoError.invalidInputLength("Ciphertext must include at least 16 bytes for tag.")}

         var outputBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil

         let result: Int32 = try ciphertext.withUnsafeBytes { dataPtr in
             try key.withUnsafeBytes { keyPtr in
                 try nonce.withUnsafeBytes { noncePtr in
                      guard let dataBase = dataPtr.baseAddress,
                            let keyBase = keyPtr.baseAddress,
                            let nonceBase = noncePtr.baseAddress else {
                           throw AeronyxCryptoError.invalidInputLength("Cannot get base address for decrypt inputs.")
                      }
                     return aeronyx_decrypt_chacha20poly1305(
                         dataBase.assumingMemoryBound(to: UInt8.self), ciphertext.count,
                         keyBase.assumingMemoryBound(to: UInt8.self), key.count,
                         nonceBase.assumingMemoryBound(to: UInt8.self), nonce.count,
                         &outputBufferPtr
                     )
                 }
             }
         }

          // Check return code (0 is success, non-zero indicates failure, likely auth tag mismatch)
         if let error = AeronyxCryptoError.from(code: result, operation: "decryptChaCha20Poly1305") {
             if let ptr = outputBufferPtr { aeronyx_free_buffer(ptr) }
             // Provide a more specific error for decryption failure
             if result == -9 { // Assuming -9 maps to AERONYX_CRYPTO_ERROR_AUTH from C header design
                  throw AeronyxCryptoError.decryptionFailed // Or authenticationFailed
             } else {
                  throw error // Throw general error for other codes
             }
         }

         // Process the plaintext buffer
         return try processOutParamBuffer(outputBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "decryptChaCha20Poly1305_plaintext")
    }

    static func deriveKey(keyMaterial: Data, salt: Data? = nil, info: Data? = nil, outputLength: Int = 32) throws -> Data {
         guard outputLength > 0 else { throw AeronyxCryptoError.invalidInputLength("Output length must be positive.") }
         var outputBufferPtr: UnsafeMutablePointer<ByteBuffer>? = nil

         // Use nested closures for safety with optional Data pointers
         let result: Int32 = try keyMaterial.withUnsafeBytes { materialPtr -> Int32 in
             guard let materialBase = materialPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for key material.") }

             // Helper to execute the FFI call within the scope of optional pointers
             func callDeriveKey(saltPtr: UnsafePointer<UInt8>?, saltLen: Int, infoPtr: UnsafePointer<UInt8>?, infoLen: Int) -> Int32 {
                 return aeronyx_derive_key(
                     materialBase.assumingMemoryBound(to: UInt8.self), keyMaterial.count,
                     saltPtr, saltLen,
                     infoPtr, infoLen,
                     outputLength,
                     &outputBufferPtr
                 )
             }

             // Manage optional salt
             if let salt = salt {
                 return try salt.withUnsafeBytes { saltPtr -> Int32 in
                      guard let saltBase = saltPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for salt.") }
                      // Manage optional info within salt scope
                      if let info = info {
                          return try info.withUnsafeBytes { infoPtr -> Int32 in
                               guard let infoBase = infoPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for info.") }
                               return callDeriveKey(saltPtr: saltBase.assumingMemoryBound(to: UInt8.self), saltLen: salt.count, infoPtr: infoBase.assumingMemoryBound(to: UInt8.self), infoLen: info.count)
                          }
                      } else { // info is nil
                          return callDeriveKey(saltPtr: saltBase.assumingMemoryBound(to: UInt8.self), saltLen: salt.count, infoPtr: nil, infoLen: 0)
                      }
                 }
             } else { // salt is nil
                  // Manage optional info when salt is nil
                  if let info = info {
                      return try info.withUnsafeBytes { infoPtr -> Int32 in
                           guard let infoBase = infoPtr.baseAddress else { throw AeronyxCryptoError.invalidInputLength("Cannot get base address for info.") }
                           return callDeriveKey(saltPtr: nil, saltLen: 0, infoPtr: infoBase.assumingMemoryBound(to: UInt8.self), infoLen: info.count)
                      }
                  } else { // both salt and info are nil
                      return callDeriveKey(saltPtr: nil, saltLen: 0, infoPtr: nil, infoLen: 0)
                  }
             }
         } // End of keyMaterial.withUnsafeBytes

         if let error = AeronyxCryptoError.from(code: result, operation: "deriveKey (HKDF)") {
             if let ptr = outputBufferPtr { aeronyx_free_buffer(ptr) }
             throw error
         }

         let derivedData = try processOutParamBuffer(outputBufferPtr, freeFunc: aeronyx_free_buffer, operationName: "deriveKey (HKDF)")
          // Check length again just in case
          guard derivedData.count == outputLength else {
               throw AeronyxCryptoError.rustInternalError("HKDF returned unexpected key length: \(derivedData.count), expected \(outputLength)")
          }
          return derivedData
    }

    // --- Combined ECDH + HKDF (Hybrid Approach using CryptoKit for ECDH) ---
    static func deriveSharedSecretAndKey(privateKeyEd: Data, serverPublicKeyEd: Data) throws -> Data {
        // 1. Convert Keys using Rust FFI
        let x25519PrivateKey = try Self.ed25519PrivateToX25519(privateKey: privateKeyEd)
        let x25519ServerPublicKey = try Self.ed25519PublicToX25519(publicKey: serverPublicKeyEd)

        // 2. Perform ECDH using CryptoKit
        // Ensure keys are correct length for CryptoKit
        guard x25519PrivateKey.count == 32 else { throw AeronyxCryptoError.conversionFailed("X25519 private key conversion yielded wrong length.") }
        guard x25519ServerPublicKey.count == 32 else { throw AeronyxCryptoError.conversionFailed("X25519 public key conversion yielded wrong length.") }

        let ckPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519PrivateKey)
        let ckPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519ServerPublicKey)
        let sharedSecret = try ckPrivateKey.sharedSecretFromKeyAgreement(with: ckPublicKey)

        // 3. Derive final key using HKDF via Rust FFI
        let info = "AERONYX-VPN-KEY".data(using: .utf8)! // Matches original server code usage pattern
        let derivedKey = try Self.deriveKey(
            keyMaterial: sharedSecret.withUnsafeBytes { Data($0) }, // Get Data from SharedSecret
            salt: nil,
            info: info,
            outputLength: 32 // Standard 32-byte key
        )
        return derivedKey
    }

    // --- Test Library Loading ---
    static func testLibraryLoading() -> String {
        // 尝试进行一个简单的调用来测试库是否正常加载
        do {
            let testData = Data([1, 2, 3, 4])
            let key = Data(repeating: 0, count: 32)
            let (_, _) = try AeronyxCrypto.encryptChaCha20Poly1305(data: testData, key: key)
            return "Library loaded successfully with all required functions"
        } catch {
            return "Library test failed: \(error.localizedDescription)"
        }
    }

    static var isLibraryLoaded: Bool {
        do {
            let testData = Data([1, 2, 3, 4])
            let key = Data(repeating: 0, count: 32)
            let _ = try AeronyxCrypto.encryptChaCha20Poly1305(data: testData, key: key)
            return true
        } catch {
            return false
        }
    }
}
