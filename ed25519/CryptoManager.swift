import Foundation
import CryptoKit
import os.log

class CryptoManager {
    private let log = OSLog(subsystem: "com.aeronyx.AeroNyx", category: "Crypto")
    private let keychain = KeychainManager()
    
    // MARK: - 密钥对常量
    
    private struct KeychainKeys {
        static let privateKey = "AeroNyx.solana.keypair.private"
        static let publicKey = "AeroNyx.solana.keypair.public"
    }
    
    // MARK: - 初始化
    
    init() {
        os_log("Initializing crypto manager", log: log, type: .debug)
    }
    
    // MARK: - 密钥对操作
    
    /// 生成新的Solana密钥对(Ed25519)并保存到Keychain
    func generateNewKeypair() throws -> (privateKey: Data, publicKey: Data, publicKeyString: String) {
        // 创建一个新的Ed25519密钥对
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // 获取密钥组件数据
        let privateKeyData = privateKey.rawRepresentation
        let publicKeyData = publicKey.rawRepresentation
        
        // 转换为字符串格式
        let privateKeyHex = privateKeyData.hexString
        let publicKeyBase58 = publicKeyData.base58EncodedString
        
        // 保存到keychain
        try keychain.saveToKeychain(key: KeychainKeys.privateKey, value: privateKeyHex)
        try keychain.saveToKeychain(key: KeychainKeys.publicKey, value: publicKeyBase58)
        
        os_log("Generated new Ed25519 keypair: %{public}@", log: log, type: .info, publicKeyBase58)
        
        return (privateKeyData, publicKeyData, publicKeyBase58)
    }
    
    /// 从Keychain加载密钥对
    func loadKeypair() throws -> (privateKey: Data, publicKey: Data, publicKeyString: String) {
        guard let privateKeyHex = keychain.loadFromKeychain(key: KeychainKeys.privateKey),
              let publicKeyBase58 = keychain.loadFromKeychain(key: KeychainKeys.publicKey) else {
            throw CryptoError.keypairNotFound
        }
        
        guard let privateKeyData = Data(hexString: privateKeyHex) else {
            throw CryptoError.invalidKeyFormat
        }
        
        // 从私钥重新生成公钥(更安全的做法)
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        
        return (privateKeyData, publicKeyData, publicKeyBase58)
    }
    
    /// 从字符串导入密钥对(支持十六进制或Base58格式)
    func importKeypair(from privateKeyString: String) throws {
        var privateKeyData: Data
        
        // 尝试解析为十六进制
        if let data = Data(hexString: privateKeyString) {
            privateKeyData = data
        }
        // 尝试解析为Base58
        else if let data = Data(base58Encoded: privateKeyString) {
            privateKeyData = data
        }
        else {
            throw CryptoError.invalidKeyFormat
        }
        
        // 验证私钥并生成公钥
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        
        // 保存到keychain
        try keychain.saveToKeychain(key: KeychainKeys.privateKey, value: privateKeyData.hexString)
        try keychain.saveToKeychain(key: KeychainKeys.publicKey, value: publicKeyData.base58EncodedString)
        
        os_log("Imported Ed25519 keypair", log: log, type: .info)
    }
    
    /// 检查是否有可用的密钥对
    func isKeypairAvailable() -> Bool {
        return keychain.loadFromKeychain(key: KeychainKeys.privateKey) != nil &&
               keychain.loadFromKeychain(key: KeychainKeys.publicKey) != nil
    }
    
    // MARK: - 加密操作
    
    /// 使用Ed25519私钥对挑战进行签名
    func sign(challenge: Data) throws -> String {
        let keypair = try loadKeypair()
        
        do {
            // 使用Rust实现进行签名
            let signature = try AeronyxCrypto.signEd25519(
                privateKey: keypair.privateKey,
                message: challenge
            )
            
            // Base58编码签名用于服务器
            return signature.base58EncodedString
        } catch {
            os_log("Signing failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.signFailed
        }
    }
    
    /// 从Ed25519密钥对和服务器公钥导出共享密钥
    func deriveSharedSecret(serverPublicKey: Data) throws -> Data {
        let keypair = try loadKeypair()
        
        do {
            // 完整的密钥派生流程
            let sharedSecret = try AeronyxCrypto.deriveSharedSecretAndKey(
                privateKeyEd: keypair.privateKey,
                serverPublicKeyEd: serverPublicKey
            )
            
            return sharedSecret
        } catch {
            os_log("Shared secret derivation failed: %{public}@", log: log, type: .error, error.localizedDescription)
            throw CryptoError.conversionFailed
        }
    }
    
    // MARK: - 会话密钥操作
    
    /// 使用共享密钥解密会话密钥
    func decryptSessionKey(encryptedKey: Data, nonce: Data, sharedSecret: Data) throws -> Data {
        do {
            // 使用Rust库的ChaCha20Poly1305解密
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
    
    // MARK: - 数据包加密/解密
    
    /// 使用会话密钥加密数据包
    func encryptPacket(_ packet: Data, with sessionKey: Data) throws -> (encrypted: Data, nonce: Data) {
        do {
            // 使用Rust库进行ChaCha20Poly1305加密
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
    
    /// 使用会话密钥解密数据包
    func decryptPacket(_ encrypted: Data, nonce: Data, with sessionKey: Data) throws -> Data {
        do {
            // 使用Rust库进行ChaCha20Poly1305解密
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

// MARK: - 错误类型

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
            return "密钥对未找到"
        case .invalidKeyFormat:
            return "无效的密钥格式"
        case .encryptionFailed:
            return "加密失败"
        case .decryptionFailed:
            return "解密或验证失败"
        case .signFailed:
            return "签名操作失败"
        case .conversionFailed(let details):
            return "密钥转换失败: \(details)"
        }
    }
}
