import Foundation
import CryptoKit
import os.log

class CryptoManager {
    private let log = OSLog(subsystem: "com.aeronyx.AeroNyx", category: "Crypto")
    private let keychain = KeychainManager()
    
    // MARK: - Keypair Constants
    
    private struct KeychainKeys {
        static let privateKey = "AeroNyx.solana.keypair.private"
        static let publicKey = "AeroNyx.solana.keypair.public"
    }
    
    // MARK: - Initialization
    
    init() {
        os_log("Initializing crypto manager", log: log, type: .debug)
    }
    
    // MARK: - Keypair Operations
    
    /// Generate a new Solana keypair (Ed25519) and save to Keychain
    func generateNewKeypair() throws -> (privateKey: Data, publicKey: Data, publicKeyString: String) {
        // Create a new Ed25519 keypair
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Get key component data
        let privateKeyData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation
        
        // Convert to string format
        let privateKeyHex = privateKeyData.hexString
        let publicKeyBase58 = publicKeyData.base58EncodedString
        
        // Save to keychain
        try keychain.saveToKeychain(key: KeychainKeys.privateKey, value: privateKeyHex)
        try keychain.saveToKeychain(key: KeychainKeys.publicKey, value: publicKeyBase58)
        
        os_log("Generated new Ed25519 keypair: %{public}@", log: log, type: .info, publicKeyBase58)
        
        return (privateKeyData, publicKeyData, publicKeyBase58)
    }
    
    /// Load keypair from Keychain
    func loadKeypair() throws -> (privateKey: Data, publicKey: Data, publicKeyString: String) {
        guard let privateKeyHex = keychain.loadFromKeychain(key: KeychainKeys.privateKey),
              let publicKeyBase58 = keychain.loadFromKeychain(key: KeychainKeys.publicKey) else {
            throw CryptoError.keypairNotFound
        }
        
        guard let privateKeyData = Data(hexString: privateKeyHex) else {
            throw CryptoError.invalidKeyFormat
        }
        
        // Regenerate public key from private key (more secure approach)
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        
        return (privateKeyData, publicKeyData, publicKeyBase58)
    }
    
    /// Import keypair from string (supports hex or Base58 format)
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
        
        // Verify private key and generate public key
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        
        // Save to keychain
        try keychain.saveToKeychain(key: KeychainKeys.privateKey, value: privateKeyData.hexString)
        try keychain.saveToKeychain(key: KeychainKeys.publicKey, value: publicKeyData.base58EncodedString)
        
        os_log("Imported Ed25519 keypair", log: log, type: .info)
    }
    
    /// Check if keypair is available
    func isKeypairAvailable() -> Bool {
        return keychain.loadFromKeychain(key: KeychainKeys.privateKey) != nil &&
               keychain.loadFromKeychain(key: KeychainKeys.publicKey) != nil
    }
    
    // MARK: - Encryption Operations
    
    /// Sign a challenge with Ed25519 private key
    func sign(challenge: Data) throws -> String {
        let keypair = try loadKeypair()
        
        do {
            // Use native implementation for signing
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keypair.privateKey)
            let signature = try privateKey.signature(for: challenge)
            
            // Base58 encode signature for server - fix this line
            return Data(signature).base58EncodedString
        } catch {
            os_log("Signing failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.signFailed
        }
    }
    
    /// Derive shared key from Ed25519 keypair and server public key
    func deriveSharedSecret(serverPublicKey: Data) throws -> Data {
        let keypair = try loadKeypair()
        
        do {
            // Use CryptoKit for ECDH
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keypair.privateKey)
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKey)
            
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            
            // Derive key using HKDF
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: "AERONYX-VPN-KEY".data(using: .utf8)!,
                outputByteCount: 32
            )
            
            // Get raw key data
            return symmetricKey.withUnsafeBytes { Data($0) }
        } catch {
            os_log("Shared secret derivation failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.conversionFailed(error.localizedDescription)
        }
    }
    
    // MARK: - Session Key Operations
    
    /// Decrypt session key using shared secret
    func decryptSessionKey(encryptedKey: Data, nonce: Data, sharedSecret: Data) throws -> Data {
        do {
            // Use CryptoKit for ChaCha20Poly1305 decryption
            let key = SymmetricKey(data: sharedSecret)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce),
                                                   ciphertext: encryptedKey.dropLast(16),
                                                   tag: encryptedKey.suffix(16))
            
            let decrypted = try ChaChaPoly.open(sealedBox, using: key)
            return decrypted
        } catch {
            os_log("Session key decryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.decryptionFailed
        }
    }
    
    // MARK: - Packet Encryption/Decryption
    
    /// Encrypt packet with session key
    func encryptPacket(_ packet: Data, with sessionKey: Data) throws -> (encrypted: Data, nonce: Data) {
        do {
            // Use CryptoKit for ChaCha20Poly1305 encryption
            let key = SymmetricKey(data: sessionKey)
            let nonce = ChaChaPoly.Nonce()
            let sealedBox = try ChaChaPoly.seal(packet, using: key, nonce: nonce)
            
            // Combine nonce, ciphertext, and tag
            var encrypted = Data()
            encrypted.append(sealedBox.ciphertext)
            encrypted.append(sealedBox.tag)
            
            return (encrypted, nonce.withUnsafeBytes { Data($0) })
        } catch {
            os_log("Packet encryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.encryptionFailed
        }
    }
    
    /// Decrypt packet with session key
    func decryptPacket(_ encrypted: Data, nonce: Data, with sessionKey: Data) throws -> Data {
        do {
            // Use CryptoKit for ChaCha20Poly1305 decryption
            let key = SymmetricKey(data: sessionKey)
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonceObj,
                                                   ciphertext: encrypted.dropLast(16),
                                                   tag: encrypted.suffix(16))
            
            let decrypted = try ChaChaPoly.open(sealedBox, using: key)
            return decrypted
        } catch {
            os_log("Packet decryption failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.decryptionFailed
        }
    }
}

// MARK: - Error Types

enum CryptoError: Error, LocalizedError {
    case keypairNotFound
    case invalidKeyFormat
    case encryptionFailed
    case decryptionFailed
    case signFailed
    case conversionFailed(String)
    
    var errorDescription: String? {
        switch self {
        case .keypairNotFound:
            return "Keypair not found"
        case .invalidKeyFormat:
            return "Invalid key format"
        case .encryptionFailed:
            return "Encryption failed"
        case .decryptionFailed:
            return "Decryption or verification failed"
        case .signFailed:
            return "Signing operation failed"
        case .conversionFailed(let details):
            return "Key conversion failed: \(details)"
        }
    }
}
