import Foundation
import CryptoKit
import os.log

class CryptoManager {
    private let log = OSLog(subsystem: "com.aeronyx.AeroNyx", category: "Crypto")
    private let keychain = KeychainManager()
    
    // MARK: - Initialization
    
    init() {
        os_log("Initializing crypto manager", log: log, type: .debug)
    }
    
    // MARK: - Key Operations
    
    func loadKeypair() throws -> (privateKey: Data, publicKey: Data, publicKeyString: String) {
        guard let privateKeyHex = keychain.loadFromKeychain(key: "AeroNyx.keypair.private"),
              let publicKeyBase58 = keychain.loadFromKeychain(key: "AeroNyx.keypair.public") else {
            throw CryptoError.keypairNotFound
        }
        
        guard let privateKeyData = Data(hexString: privateKeyHex),
              let publicKeyData = Data(base58Encoded: publicKeyBase58) else {
            throw CryptoError.invalidKeyFormat
        }
        
        return (privateKeyData, publicKeyData, publicKeyBase58)
    }
    
    func generateNewKeypair() throws {
        // Create a new Ed25519 key pair
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Get key components as data
        let privateKeyData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation
        
        // Save to keychain
        try keychain.saveToKeychain(key: "AeroNyx.keypair.private", value: privateKeyData.hexString)
        try keychain.saveToKeychain(key: "AeroNyx.keypair.public", value: publicKeyData.base58EncodedString)
        
        os_log("Generated new Ed25519 keypair", log: log, type: .info)
    }
    
    func importKeypair(from privateKeyString: String) throws {
        var privateKeyData: Data
        
        // Try to parse as hex
        if let data = Data(hexString: privateKeyString) {
            privateKeyData = data
        }
        // Try to parse as Base58
        else if let data = Data(base58Encoded: privateKeyString) {
            privateKeyData = data
        }
        else {
            throw CryptoError.invalidKeyFormat
        }
        
        // Validate by creating a CryptoKit key
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        
        // Save to keychain
        try keychain.saveToKeychain(key: "AeroNyx.keypair.private", value: privateKeyData.hexString)
        try keychain.saveToKeychain(key: "AeroNyx.keypair.public", value: publicKey.rawRepresentation.base58EncodedString)
        
        os_log("Imported Ed25519 keypair", log: log, type: .info)
    }
    
    func sign(challenge: Data) throws -> String {
        let keypair = try loadKeypair()
        
        do {
            // Use the Rust implementation for signing
            let signature = try AeronyxCrypto.signEd25519(
                privateKey: keypair.privateKey,
                message: challenge
            )
            
            // Base58 encode signature for the server
            return signature.base58EncodedString
        } catch {
            os_log("Signing failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.signFailed
        }
    }
    
    // MARK: - Shared Secret Derivation
    
    func deriveSharedSecret(serverPublicKey: Data) throws -> Data {
        let keypair = try loadKeypair()
        
        do {
            // Convert Ed25519 private key to X25519 using Rust
            let x25519PrivateKey = try AeronyxCrypto.ed25519PrivateToX25519(
                privateKey: keypair.privateKey
            )
            
            // Convert Ed25519 server public key to X25519 using Rust
            let x25519ServerPublicKey = try AeronyxCrypto.ed25519PublicToX25519(
                publicKey: serverPublicKey
            )
            
            // Use Swift's CryptoKit for X25519 key agreement
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519PrivateKey)
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519ServerPublicKey)
            
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            
            // Derive final key using HKDF
            let keyData = try AeronyxCrypto.deriveKey(
                keyMaterial: sharedSecret.withUnsafeBytes { Data($0) },
                info: "AERONYX-VPN-KEY".data(using: .utf8)!,
                outputLength: 32
            )
            
            return keyData
        } catch {
            os_log("Shared secret derivation failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.conversionFailed
        }
    }
    
    // MARK: - Session Key Encryption
    
    func encryptSessionKey(sessionKey: Data, sharedSecret: Data) throws -> (encryptedKey: Data, nonce: Data) {
        do {
            // Use Rust for ChaCha20-Poly1305 encryption
            let (encryptedKey, nonce) = try AeronyxCrypto.encryptChaCha20Poly1305(
                data: sessionKey,
                key: sharedSecret
            )
            
            return (encryptedKey, nonce)
        } catch {
            os_log("Session key encryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.encryptionFailed
        }
    }
    
    func decryptSessionKey(encryptedKey: Data, nonce: Data, sharedSecret: Data) throws -> Data {
        do {
            // Use Rust for ChaCha20-Poly1305 decryption
            let decrypted = try AeronyxCrypto.decryptChaCha20Poly1305(
                ciphertext: encryptedKey,
                key: sharedSecret,
                nonce: nonce
            )
            
            return decrypted
        } catch {
            os_log("Session key decryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.decryptionFailed
        }
    }
    
    // MARK: - Packet Encryption/Decryption
    
    func encryptPacket(_ packet: Data, with sessionKey: Data) throws -> (encrypted: Data, nonce: Data) {
        do {
            // Use Rust for ChaCha20-Poly1305 encryption
            let (ciphertext, nonce) = try AeronyxCrypto.encryptChaCha20Poly1305(
                data: packet,
                key: sessionKey
            )
            
            return (ciphertext, nonce)
        } catch {
            os_log("Packet encryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.encryptionFailed
        }
    }
    
    func decryptPacket(_ encrypted: Data, nonce: Data, with sessionKey: Data) throws -> Data {
        do {
            // Use Rust for ChaCha20-Poly1305 decryption
            let decrypted = try AeronyxCrypto.decryptChaCha20Poly1305(
                ciphertext: encrypted,
                key: sessionKey,
                nonce: nonce
            )
            
            return decrypted
        } catch {
            os_log("Packet decryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.decryptionFailed
        }
    }
}

// MARK: - Errors

enum CryptoError: Error {
    case keypairNotFound
    case invalidKeyFormat
    case encryptionFailed
    case decryptionFailed
    case signFailed
    case conversionFailed
}
