import Foundation

// Data extension for convenient data conversion
extension Data {
    // Initialize from hex string
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
    
    // Convert to hex string
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    // Initialize from Base58 encoded string
    init?(base58Encoded string: String) {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        let alphabetBytes = [UInt8](alphabet.utf8)
        
        // Create character to index mapping for performance
        var alphabetMap = [UInt8: Int]()
        for (i, char) in alphabetBytes.enumerated() {
            alphabetMap[char] = i
        }
        
        let stringBytes = [UInt8](string.utf8)
        
        // Count leading zeros
        var leadingZeroCount = 0
        for char in stringBytes {
            if char == alphabetBytes[0] {
                leadingZeroCount += 1
            } else {
                break
            }
        }
        
        // Convert from Base58 to decimal
        var value = [UInt8](repeating: 0, count: string.count * 733 / 1000 + 1)
        var length = 1
        
        // Skip leading '1's
        for charIndex in leadingZeroCount..<stringBytes.count {
            guard let digit = alphabetMap[stringBytes[charIndex]] else {
                return nil // Invalid Base58 character
            }
            
            var carry = digit
            var i = 0
            
            // Apply "multiply base add digit" algorithm
            for j in (0..<length).reversed() {
                carry += 58 * Int(value[j])
                value[j] = UInt8(carry % 256)
                carry /= 256
                
                if carry == 0 && i < j {
                    i = j
                }
            }
            
            if carry > 0 {
                // Need to add another byte
                for j in (0..<length).reversed() {
                    value[j + 1] = value[j]
                }
                value[0] = UInt8(carry)
                length += 1
            }
        }
        
        // Create result data
        var result = Data(repeating: 0, count: leadingZeroCount)
        result.append(contentsOf: value[0..<length])
        
        self = result
    }
    
    // Convert to Base58 encoded string
    var base58EncodedString: String {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bytes = [UInt8](self)
        var zerosCount = 0
        
        // Count leading zeros
        while zerosCount < bytes.count && bytes[zerosCount] == 0 {
            zerosCount += 1
        }
        
        // Create encoded result for zeros
        let encodedZeros = String(repeating: alphabet.first!, count: zerosCount)
        
        // If only zeros, return directly
        if zerosCount == bytes.count {
            return encodedZeros
        }
        
        // Create a new array with valid data
        bytes = Array(bytes[zerosCount...])
        
        // Calculate max possible encoded length (38% longer than base256)
        let maxOutputLength = Int(Double(bytes.count) * 1.38) + 1
        var output = [UInt8](repeating: 0, count: maxOutputLength)
        var outputLength = 0
        
        // Base256 to Base58 conversion
        for byte in bytes {
            var carry = Int(byte)
            var i = 0
            
            // Iterate through output array and multiply each position by 256
            for j in (0..<outputLength).reversed() {
                carry += 256 * Int(output[j])
                output[j] = UInt8(carry % 58)
                carry /= 58
                
                if carry == 0 && i < j {
                    i = j
                }
            }
            
            // Handle carry if any
            while carry > 0 {
                output.insert(UInt8(carry % 58), at: 0)
                carry /= 58
                outputLength += 1
            }
            
            outputLength = outputLength == 0 ? 1 : outputLength
        }
        
        // Convert to string
        var result = encodedZeros
        for i in 0..<outputLength {
            let index = alphabet.index(alphabet.startIndex, offsetBy: Int(output[i]))
            result.append(alphabet[index])
        }
        
        return result
    }
}
