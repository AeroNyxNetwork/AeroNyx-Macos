import Foundation
//ed25519/Data+Extension
// Extensions for Data for convenient conversions
extension Data {
    // Initialize data from a hex string
    init?(hexString: String) {
        let hexString = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hexString.count % 2 == 0 else { return nil }
        
        var data = Data()
        var startIndex = hexString.startIndex
        
        while startIndex < hexString.endIndex {
            let endIndex = hexString.index(startIndex, offsetBy: 2)
            let byteString = hexString[startIndex..<endIndex]
            
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            
            startIndex = endIndex
        }
        
        self = data
    }
    
    // Convert data to hex string
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    // Simple base58 encoding - you'll need a more complete implementation for production
    var base58EncodedString: String {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bytes = [UInt8](self)
        var zerosCount = 0
        
        while zerosCount < bytes.count && bytes[zerosCount] == 0 {
            zerosCount += 1
        }
        
        bytes = Array(bytes[zerosCount...])
        var length = 2 * bytes.count
        let encodedZeros = String(repeating: alphabet.first!, count: zerosCount)
        
        guard !bytes.isEmpty else {
            return encodedZeros
        }
        
        var encoded = [Character](repeating: "1", count: length)
        var encodedLen = 0
        
        for _ in 0..<length {
            var carry = 0
            for j in 0..<bytes.count {
                carry = carry * 256 + Int(bytes[j])
                bytes[j] = UInt8(carry / 58)
                carry %= 58
            }
            
            encoded[encodedLen] = alphabet[carry]
            encodedLen += 1
            
            carry = 0
            for j in 0..<bytes.count {
                if bytes[j] != 0 {
                    carry = 1
                    break
                }
            }
            
            if carry == 0 {
                break
            }
        }
        
        return encodedZeros + String(encoded[..<encodedLen].reversed())
    }
