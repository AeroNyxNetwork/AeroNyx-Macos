import Foundation
import Security

class KeychainManager {
    enum KeychainError: Error {
        case saveFailure(OSStatus)
        case readFailure(OSStatus)
        case deleteFailure(OSStatus)
        case itemNotFound
        case unexpectedData
        case invalidData
    }
    
    /// 将字符串保存到Keychain
    func saveToKeychain(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.invalidData
        }
        
        // 查询条件
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aeronyx.AeroNyx"
        ]
        
        // 先尝试删除旧值
        SecItemDelete(query as CFDictionary)
        
        // 添加属性
        var addQuery = query
        addQuery[kSecValueData as String] = data
        
        // 添加访问控制
        #if os(iOS)
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #else
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        #endif
        
        // 添加新项
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailure(status)
        }
    }
    
    /// 从Keychain读取字符串
    func loadFromKeychain(key: String) -> String? {
        // 查询条件
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aeronyx.AeroNyx",
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        guard let data = item as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    /// 从Keychain删除项
    func removeFromKeychain(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aeronyx.AeroNyx"
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailure(status)
        }
    }
}
