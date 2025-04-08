import Foundation

// Data扩展，用于便捷的数据转换
extension Data {
    // 初始化自十六进制字符串
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
    
    // 转换为十六进制字符串
    var hexString: String {
        map { String(format: "%02hhx", $0) }.joined()
    }
    
    // 初始化自Base58编码的字符串
    init?(base58Encoded string: String) {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        let alphabetBytes = [UInt8](alphabet.utf8)
        
        // 创建字符到索引的映射，提高性能
        var alphabetMap = [UInt8: Int]()
        for (i, char) in alphabetBytes.enumerated() {
            alphabetMap[char] = i
        }
        
        let stringBytes = [UInt8](string.utf8)
        
        // 计算前导零
        var leadingZeroCount = 0
        for char in stringBytes {
            if char == alphabetBytes[0] {
                leadingZeroCount += 1
            } else {
                break
            }
        }
        
        // 从Base58转换到十进制
        var value = [UInt8](repeating: 0, count: string.count * 733 / 1000 + 1)
        var length = 1
        
        // 跳过前导'1'
        for charIndex in leadingZeroCount..<stringBytes.count {
            guard let digit = alphabetMap[stringBytes[charIndex]] else {
                return nil // 无效的Base58字符
            }
            
            var carry = digit
            var i = 0
            
            // 应用"乘基数加数字"算法
            for j in (0..<length).reversed() {
                carry += 58 * Int(value[j])
                value[j] = UInt8(carry % 256)
                carry /= 256
                
                if carry == 0 && i < j {
                    i = j
                }
            }
            
            if carry > 0 {
                // 需要增加一个额外的字节
                for j in (0..<length).reversed() {
                    value[j + 1] = value[j]
                }
                value[0] = UInt8(carry)
                length += 1
            }
        }
        
        // 创建结果数据
        // 创建结果数据
                var result = Data(repeating: 0, count: leadingZeroCount)
                result.append(contentsOf: value[0..<length])
                
                self = result
            }
            
            // 转换为Base58编码的字符串
            var base58EncodedString: String {
                let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                var bytes = [UInt8](self)
                var zerosCount = 0
                
                // 计算前导0的数量
                while zerosCount < bytes.count && bytes[zerosCount] == 0 {
                    zerosCount += 1
                }
                
                // 为前导0创建编码结果
                let encodedZeros = String(repeating: alphabet.first!, count: zerosCount)
                
                // 如果只有前导0，直接返回
                if zerosCount == bytes.count {
                    return encodedZeros
                }
                
                // 用有效数据创建一个新数组
                bytes = Array(bytes[zerosCount...])
                
                // 计算编码后可能的最大长度(以58为基数，比以256为基数长约38%)
                let maxOutputLength = Int(Double(bytes.count) * 1.38) + 1
                var output = [UInt8](repeating: 0, count: maxOutputLength)
                var outputLength = 0
                
                // Base256 到 Base58 转换
                for byte in bytes {
                    var carry = Int(byte)
                    var i = 0
                    
                    // 遍历输出数组，将每个位置乘以256并加上进位
                    for j in (0..<outputLength).reversed() {
                        carry += 256 * Int(output[j])
                        output[j] = UInt8(carry % 58)
                        carry /= 58
                        
                        if carry == 0 && i < j {
                            i = j
                        }
                    }
                    
                    // 如果有进位，增加输出长度
                    while carry > 0 {
                        output.insert(UInt8(carry % 58), at: 0)
                        carry /= 58
                        outputLength += 1
                    }
                    
                    outputLength = outputLength == 0 ? 1 : outputLength
                }
                
                // 转换为字符串
                var result = encodedZeros
                for i in 0..<outputLength {
                    let index = alphabet.index(alphabet.startIndex, offsetBy: Int(output[i]))
                    result.append(alphabet[index])
                }
                
                return result
            }
        }
