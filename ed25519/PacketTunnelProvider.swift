import NetworkExtension
import os.log
import Foundation

// MARK: - 协议数据包结构

/// 协议数据包类型
enum PacketType: String, Codable {
    case auth = "Auth"
    case challenge = "Challenge"
    case challengeResponse = "ChallengeResponse"
    case ipAssign = "IpAssign"
    case data = "Data"
    case error = "Error"
    case ping = "Ping"
    case pong = "Pong"
    case disconnect = "Disconnect"
}

/// 基础数据包结构
struct BasePacket: Codable {
    let type: PacketType
}

/// 认证数据包
struct AuthPacket: Codable {
    let type = PacketType.auth
    let publicKey: String
    let clientVersion: String
    let platform: String
}

/// 挑战数据包
struct ChallengePacket: Codable {
    let type = PacketType.challenge
    let data: String  // Base64编码的挑战数据
    let serverKey: String  // 服务器Ed25519公钥(Base58编码)
    let id: String  // 挑战ID
    let expiresAt: Int64  // 过期时间戳
}

/// 挑战响应数据包
struct ChallengeResponsePacket: Codable {
    let type = PacketType.challengeResponse
    let signature: String  // Base58编码的签名
    let publicKey: String  // 客户端公钥(Base58编码)
    let challengeId: String  // 挑战ID
}

/// IP分配数据包
struct IpAssignPacket: Codable {
    let type = PacketType.ipAssign
    let ipAddress: String  // 分配的IP地址
    let subnetMask: String  // 子网掩码
    let gateway: String  // 网关地址
    let dns: [String]  // DNS服务器地址
    let encryptedSessionKey: String  // Base64编码的加密会话密钥
    let keyNonce: String  // Base64编码的会话密钥nonce
    let sessionId: String  // 会话ID
    let leaseDuration: Int64  // 租约时长(秒)
}

/// 数据包
struct DataPacket: Codable {
    let type = PacketType.data
    let encrypted: String  // Base64编码的加密数据
    let nonce: String  // Base64编码的nonce
    let counter: Int64  // 数据包计数器
}

/// 错误数据包
struct ErrorPacket: Codable {
    let type = PacketType.error
    let code: Int
    let message: String
}

/// 断开连接数据包
struct DisconnectPacket: Codable {
    let type = PacketType.disconnect
    let reason: String
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "com.aeronyx.AeroNyx.PacketTunnel", category: "Provider")
    private var cryptoManager: CryptoManager?
    private var sessionKey: Data?
    private var webSocketTask: URLSessionWebSocketTask?
    private var socketQueue = DispatchQueue(label: "com.aeronyx.AeroNyx.SocketQueue")
    private var isProcessingPackets = false
    private var packetCounter: Int64 = 0
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5
    private var serverPublicKey: Data?
    private var sessionId: String?
    
    // MARK: - 会话生命周期
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting tunnel...", log: log, type: .info)
        
        // 初始化加密管理器
        cryptoManager = CryptoManager()
        
        // 开始与服务器握手
        startServerHandshake { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                os_log("Server handshake failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            
            os_log("Tunnel established successfully", log: self.log, type: .info)
            self.startPacketForwarding()
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel with reason: %{public}d", log: log, type: .info, reason.rawValue)
        
        // 发送断开连接消息
        if let webSocketTask = webSocketTask, sessionId != nil {
            let disconnectPacket = DisconnectPacket(reason: "Client initiated disconnect")
            sendJsonPacket(disconnectPacket) { _ in
                // 无论发送成功与否都继续清理
                self.cleanupResources()
                completionHandler()
            }
        } else {
            cleanupResources()
            completionHandler()
        }
    }
    
    private func cleanupResources() {
        // 停止数据包处理
        isProcessingPackets = false
        
        // 关闭WebSocket连接
        webSocketTask?.cancel()
        webSocketTask = nil
        
        // 清理资源
        sessionKey = nil
        serverPublicKey = nil
        sessionId = nil
        packetCounter = 0
        reconnectAttempts = 0
    }
    
    // MARK: - 服务器握手
    
    private func startServerHandshake(completion: @escaping (Error?) -> Void) {
        // 1. 连接到服务器
        guard let url = URL(string: "wss://your-vpn-server.com/connect") else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1000, userInfo: [NSLocalizedDescriptionKey: "Invalid server URL"]))
            return
        }
        
        guard let crypto = cryptoManager else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Crypto manager not initialized"]))
            return
        }
        
        // 加载密钥对
        let keypair: (privateKey: Data, publicKey: Data, publicKeyString: String)
        do {
            keypair = try crypto.loadKeypair()
        } catch {
            os_log("Failed to load keypair: %{public}@", log: log, type: .error, error.localizedDescription)
            completion(error)
            return
        }
        
        // 创建WebSocket连接
        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        
        // 2. 发送Auth包
        let authPacket = AuthPacket(
            publicKey: keypair.publicKeyString,
            clientVersion: "1.0.0",
            platform: "macOS"
        )
        
        sendJsonPacket(authPacket) { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                os_log("Failed to send Auth packet: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completion(error)
                return
            }
            
            // 3. 接收Challenge包
            self.receiveJsonPacket { result in
                switch result {
                case .success(let packetData):
                    do {
                        // 解析为基础数据包以获取类型
                        let decoder = JSONDecoder()
                        let basePacket = try decoder.decode(BasePacket.self, from: packetData)
                        
                        switch basePacket.type {
                        case .challenge:
                            // 解析为完整挑战包
                            let challengePacket = try decoder.decode(ChallengePacket.self, from: packetData)
                            self.handleChallenge(challengePacket, privateKey: keypair.privateKey, completion: completion)
                        case .error:
                            let errorPacket = try decoder.decode(ErrorPacket.self, from: packetData)
                            let error = NSError(domain: "com.aeronyx.AeroNyx", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                            completion(error)
                        default:
                            let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1002, userInfo: [NSLocalizedDescriptionKey: "Expected Challenge packet, got \(basePacket.type.rawValue)"]])
                            completion(error)
                        }
                    } catch {
                        os_log("Failed to parse server response: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        completion(error)
                    }
                case .failure(let error):
                    os_log("WebSocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    completion(error)
                }
            }
        }
    }
    
    private func handleChallenge(_ challengePacket: ChallengePacket, privateKey: Data, completion: @escaping (Error?) -> Void) {
        guard let crypto = cryptoManager else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1003, userInfo: [NSLocalizedDescriptionKey: "Crypto manager not initialized"]))
            return
        }
        
        do {
            // 1. 解码Base64挑战数据
            guard let challengeData = Data(base64Encoded: challengePacket.data) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1004, userInfo: [NSLocalizedDescriptionKey: "Invalid challenge data format"]])
            }
            
            // 2. 解码Base58服务器公钥
            guard let serverPublicKeyData = Data(base58Encoded: challengePacket.serverKey) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1005, userInfo: [NSLocalizedDescriptionKey: "Invalid server key format"]])
            }
            
            // 保存服务器公钥用于后续密钥派生
            self.serverPublicKey = serverPublicKeyData
            
            // 3. 签名挑战数据
            let signature = try crypto.sign(challenge: challengeData)
            
            // 4. 构造并发送ChallengeResponse包
            let keypair = try crypto.loadKeypair()
            let responsePacket = ChallengeResponsePacket(
                signature: signature,
                publicKey: keypair.publicKeyString,
                challengeId: challengePacket.id
            )
            
            sendJsonPacket(responsePacket) { [weak self] error in
                guard let self = self else { return }
                
                if let error = error {
                    os_log("Failed to send ChallengeResponse: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    completion(error)
                    return
                }
                
                // 5. 接收IpAssign包
                self.receiveJsonPacket { result in
                    switch result {
                    case .success(let packetData):
                        do {
                            // 解析为基础数据包以获取类型
                            let decoder = JSONDecoder()
                            let basePacket = try decoder.decode(BasePacket.self, from: packetData)
                            
                            switch basePacket.type {
                            case .ipAssign:
                                // 解析为完整IP分配包
                                let ipAssignPacket = try decoder.decode(IpAssignPacket.self, from: packetData)
                                self.handleIpAssign(ipAssignPacket, completion: completion)
                            case .error:
                                let errorPacket = try decoder.decode(ErrorPacket.self, from: packetData)
                                let error = NSError(domain: "com.aeronyx.AeroNyx", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                                completion(error)
                            default:
                                let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1006, userInfo: [NSLocalizedDescriptionKey: "Expected IpAssign packet, got \(basePacket.type.rawValue)"]])
                                completion(error)
                            }
                        } catch {
                            os_log("Failed to parse server response: %{public}@", log: self.log, type: .error, error.localizedDescription)
                            completion(error)
                        }
                    case .failure(let error):
                        os_log("WebSocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        completion(error)
                    }
                }
            }
        } catch {
            os_log("Challenge processing error: %{public}@", log: log, type: .error, error.localizedDescription)
            completion(error)
        }
    }
    
    private func handleIpAssign(_ ipAssignPacket: IpAssignPacket, completion: @escaping (Error?) -> Void) {
        guard let crypto = cryptoManager, let serverPublicKey = self.serverPublicKey else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1007, userInfo: [NSLocalizedDescriptionKey: "Missing crypto manager or server public key"]))
            return
        }
        
        do {
            // 1. 解码Base64加密会话密钥和nonce
            guard let encryptedSessionKeyData = Data(base64Encoded: ipAssignPacket.encryptedSessionKey),
                  let keyNonceData = Data(base64Encoded: ipAssignPacket.keyNonce) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1008, userInfo: [NSLocalizedDescriptionKey: "Invalid session key format"]])
            }
            
            // 2. 派生共享密钥
            let sharedSecret = try crypto.deriveSharedSecret(serverPublicKey: serverPublicKey)
            
            // 3. 解密会话密钥
            self.sessionKey = try crypto.decryptSessionKey(
                encryptedKey: encryptedSessionKeyData,
                nonce: keyNonceData,
                sharedSecret: sharedSecret
            )
            
            // 保存会话ID
            self.sessionId = ipAssignPacket.sessionId
            
            // 4. 配置隧道网络设置
            let settings = createTunnelSettings(ipAssign: ipAssignPacket)
            
            setTunnelNetworkSettings(settings) { error in
                if let error = error {
                    os_log("Failed to set tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    completion(error)
                    return
                }
                
                // 握手成功完成
                os_log("Handshake completed successfully, tunnel configured", log: self.log, type: .info)
                completion(nil)
                
                // 开始监听服务器数据包
                self.startReceivingPackets()
            }
        } catch {
            os_log("IP assign processing error: %{public}@", log: log, type: .error, error.localizedDescription)
            completion(error)
        }
    }
    
    private func createTunnelSettings(ipAssign: IpAssignPacket) -> NEPacketTunnelNetworkSettings {
        // 使用服务器提供的信息配置隧道
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "your-vpn-server.com") // 实际VPN服务器地址
        
        // 配置IPv4
        settings.ipv4Settings = NEIPv4Settings(
            addresses: [ipAssign.ipAddress],
            subnetMasks: [ipAssign.subnetMask]
        )
        
        if ipAssign.gateway.isEmpty == false {
            settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings?.excludedRoutes = [] // 可选，根据服务器配置添加
        }
        
        // 配置DNS
        if !ipAssign.dns.isEmpty {
            settings.dnsSettings = NEDNSSettings(servers: ipAssign.dns)
        }
        
        return settings
    }
    
    // MARK: - 数据包处理
    
    private func startPacketForwarding() {
        guard !isProcessingPackets else { return }
        isProcessingPackets = true
        
        // 启动数据包转发循环
        readPackets()
    }
    
    private func readPackets() {
        // 从TUN接口读取数据包
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isProcessingPackets else { return }
            
            self.socketQueue.async {
                self.processAndSendPackets(packets, protocols: protocols)
                // 继续读取更多数据包
                self.readPackets()
            }
        }
    }
    
    private func startReceivingPackets() {
        receiveWebSocketMessage { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success(let message):
                self.handleWebSocketMessage(message)
                // 继续接收
                self.startReceivingPackets()
            case .failure(let error):
                os_log("WebSocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                self.handleConnectionError(error)
            }
        }
    }
    
    private func handleWebSocketMessage(_ message: URLSessionWebSocketTask.Message) {
        switch message {
        case .data(let data):
            handleWebSocketData(data)
        case .string(let string):
            if let data = string.data(using: .utf8) {
                handleWebSocketData(data)
            } else {
                os_log("Received string cannot be converted to data", log: log, type: .error)
            }
        @unknown default:
            os_log("Unknown WebSocket message type", log: log, type: .error)
        }
    }
    
    private func handleWebSocketData(_ data: Data) {
        do {
            // 解析为基础数据包以获取类型
            let decoder = JSONDecoder()
            let basePacket = try decoder.decode(BasePacket.self, from: data)
            
            switch basePacket.type {
            case .data:
                // 解析为数据包
                let dataPacket = try decoder.decode(DataPacket.self, from: data)
                handleDataPacket(dataPacket)
            case .ping:
                // 回应Ping
                sendJsonPacket(BasePacket(type: .pong)) { error in
                    if let error = error {
                        self.log.error("Failed to send Pong: %{public}@", error.localizedDescription)
                    }
                }
            case .error:
                let errorPacket = try decoder.decode(ErrorPacket.self, from: data)
                os_log("Received error packet: %{public}@", log: log, type: .error, errorPacket.message)
            case .disconnect:
                let disconnectPacket = try decoder.decode(DisconnectPacket.self, from: data)
                os_log("Received disconnect: %{public}@", log: log, type: .info, disconnectPacket.reason)
                // 重新连接
                handleConnectionError(NSError(domain: "com.aeronyx.AeroNyx", code: 1009, userInfo: [NSLocalizedDescriptionKey: "Server initiated disconnect: \(disconnectPacket.reason)"]))
            default:
                os_log("Unexpected packet type: %{public}@", log: log, type: .error, basePacket.type.rawValue)
            }
        } catch {
            os_log("Failed to parse packet: %{public}@", log: log, type: .error, error.localizedDescription)
        }
    }
    
    private func handleDataPacket(_ dataPacket: DataPacket) {
            guard let sessionKey = self.sessionKey,
                  let crypto = self.cryptoManager else {
                os_log("Cannot process packet: missing session key or crypto manager", log: log, type: .error)
                return
            }
            
            do {
                // 解码Base64数据
                guard let encryptedData = Data(base64Encoded: dataPacket.encrypted),
                      let nonceData = Data(base64Encoded: dataPacket.nonce) else {
                    throw NSError(domain: "com.aeronyx.AeroNyx", code: 1010, userInfo: [NSLocalizedDescriptionKey: "Invalid packet encoding"]])
                }
                
                // 解密数据包
                let decryptedData = try crypto.decryptPacket(encryptedData, nonce: nonceData, with: sessionKey)
                
                // 写入TUN接口
                self.packetFlow.writePackets([decryptedData], withProtocols: [NSNumber(value: AF_INET)])
            } catch {
                os_log("Failed to decrypt packet: %{public}@", log: log, type: .error, error.localizedDescription)
            }
        }
        
        private func processAndSendPackets(_ packets: [Data], protocols: [NSNumber]) {
            guard let sessionKey = self.sessionKey,
                  let crypto = self.cryptoManager,
                  let webSocketTask = self.webSocketTask,
                  !packets.isEmpty else {
                return
            }
            
            for (i, packet) in packets.enumerated() {
                do {
                    // 加密数据包
                    let (encrypted, nonce) = try crypto.encryptPacket(packet, with: sessionKey)
                    
                    // 构造DataPacket结构
                    let dataPacket = DataPacket(
                        encrypted: encrypted.base64EncodedString(),
                        nonce: nonce.base64EncodedString(),
                        counter: OSAtomicIncrement64(&packetCounter)
                    )
                    
                    // 序列化并发送
                    sendJsonPacket(dataPacket) { error in
                        if let error = error {
                            os_log("Failed to send encrypted packet: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        }
                    }
                } catch {
                    os_log("Failed to encrypt packet: %{public}@", log: self.log, type: .error, error.localizedDescription)
                }
            }
        }
        
        // MARK: - WebSocket 辅助方法
        
        private func receiveWebSocketMessage(completion: @escaping (Result<URLSessionWebSocketTask.Message, Error>) -> Void) {
            webSocketTask?.receive(completionHandler: { result in
                completion(result)
            })
        }
        
        private func receiveJsonPacket(completion: @escaping (Result<Data, Error>) -> Void) {
            receiveWebSocketMessage { result in
                switch result {
                case .success(let message):
                    switch message {
                    case .data(let data):
                        completion(.success(data))
                    case .string(let string):
                        if let data = string.data(using: .utf8) {
                            completion(.success(data))
                        } else {
                            let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1011, userInfo: [NSLocalizedDescriptionKey: "Received string cannot be converted to data"])
                            completion(.failure(error))
                        }
                    @unknown default:
                        let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1012, userInfo: [NSLocalizedDescriptionKey: "Unknown WebSocket message type"])
                        completion(.failure(error))
                    }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
        
        private func sendJsonPacket<T: Encodable>(_ packet: T, completion: @escaping (Error?) -> Void) {
            do {
                let encoder = JSONEncoder()
                let jsonData = try encoder.encode(packet)
                
                if let jsonString = String(data: jsonData, encoding: .utf8) {
                    webSocketTask?.send(.string(jsonString)) { error in
                        completion(error)
                    }
                } else {
                    throw NSError(domain: "com.aeronyx.AeroNyx", code: 1013, userInfo: [NSLocalizedDescriptionKey: "Failed to encode JSON as string"])
                }
            } catch {
                os_log("JSON serialization error: %{public}@", log: log, type: .error, error.localizedDescription)
                completion(error)
            }
        }
        
        private func handleConnectionError(_ error: Error) {
            os_log("Connection error, attempting to reconnect: %{public}@", log: log, type: .error, error.localizedDescription)
            
            // 关闭当前WebSocket
            webSocketTask?.cancel()
            webSocketTask = nil
            
            // 检查重连次数
            if reconnectAttempts >= maxReconnectAttempts {
                os_log("Maximum reconnection attempts reached (%d). Giving up.", log: log, type: .error, maxReconnectAttempts)
                // 清理资源
                cleanupResources()
                return
            }
            
            reconnectAttempts += 1
            
            // 等待延迟后重新连接
            let delay = Double(min(30, pow(2.0, Double(reconnectAttempts)))) // 指数退避
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self else { return }
                
                // 重置部分状态
                self.sessionKey = nil
                self.serverPublicKey = nil
                self.packetCounter = 0
                
                // 重新开始握手
                self.startServerHandshake { error in
                    if let error = error {
                        os_log("Reconnection failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        self.handleConnectionError(error) // 递归重试
                    } else {
                        os_log("Reconnection successful", log: self.log, type: .info)
                        self.reconnectAttempts = 0 // 重置重连计数
                        self.startPacketForwarding()
                    }
                }
            }
        }
        
        // MARK: - 应用交互
        
        override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
            do {
                guard let json = try JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                      let type = json["type"] as? String else {
                    completionHandler?(nil)
                    return
                }
                
                switch type {
                case "status":
                    // 返回VPN状态
                    let status: [String: Any] = [
                        "connected": (sessionKey != nil),
                        "sessionId": sessionId ?? "",
                        "assignedIp": getAssignedIp() ?? "未分配"
                    ]
                    
                    if let responseData = try? JSONSerialization.data(withJSONObject: status, options: []) {
                        completionHandler?(responseData)
                    } else {
                        completionHandler?(nil)
                    }
                    
                case "disconnect":
                    // 手动断开连接
                    stopTunnel(with: .userInitiated) {
                        completionHandler?(nil)
                    }
                    
                case "ping":
                    // 发送Ping到服务器
                    sendJsonPacket(BasePacket(type: .ping)) { error in
                        var response: [String: Any] = ["success": error == nil]
                        if let error = error {
                            response["error"] = error.localizedDescription
                        }
                        
                        if let responseData = try? JSONSerialization.data(withJSONObject: response, options: []) {
                            completionHandler?(responseData)
                        } else {
                            completionHandler?(nil)
                        }
                    }
                    
                default:
                    os_log("Unknown message type: %{public}@", log: log, type: .error, type)
                    completionHandler?(nil)
                }
            } catch {
                os_log("Failed to parse app message: %{public}@", log: log, type: .error, error.localizedDescription)
                completionHandler?(nil)
            }
        }
        
        private func getAssignedIp() -> String? {
            guard let settings = self.protocolConfiguration as? NETunnelProviderProtocol,
                  let networkSettings = settings.providerConfiguration?["NetworkSettings"] as? [String: Any],
                  let ipv4Settings = networkSettings["IPv4Settings"] as? [String: Any],
                  let addresses = ipv4Settings["Addresses"] as? [String],
                  let address = addresses.first else {
                return nil
            }
            
            return address
        }
    }
