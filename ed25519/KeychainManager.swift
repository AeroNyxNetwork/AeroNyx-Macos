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
    
    /// Save string to Keychain
    func saveToKeychain(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.invalidData
        }
        
        // Query parameters
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "com.aeronyx.AeroNyx"
        ]
        
        // Try to delete old value first
        SecItemDelete(query as CFDictionary)
        
        // Add attributes
        var addQuery = query
        addQuery[kSecValueData as String] = data
        
        // Add access control
        #if os(iOS)
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        #else
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        #endif
        
        // Add new item
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailure(status)
        }
    }
    
    /// Read string from Keychain
    func loadFromKeychain(key: String) -> String? {
        // Query parameters
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
    
    /// Remove item from Keychain
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
