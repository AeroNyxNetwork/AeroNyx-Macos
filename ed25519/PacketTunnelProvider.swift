import NetworkExtension
import os.log
import Foundation


/// Protocol packet types
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

/// Base packet structure
struct BasePacket: Codable {
    let type: PacketType
}

/// Authentication packet
struct AuthPacket: Codable {
    let type = PacketType.auth
    let publicKey: String
    let clientVersion: String
    let platform: String
}

/// Challenge packet
struct ChallengePacket: Codable {
    let type = PacketType.challenge
    let data: String  // Base64 encoded challenge data
    let serverKey: String  // Server Ed25519 public key (Base58 encoded)
    let id: String  // Challenge ID
    let expiresAt: Int64  // Expiration timestamp
}

/// Challenge response packet
struct ChallengeResponsePacket: Codable {
    let type = PacketType.challengeResponse
    let signature: String  // Base58 encoded signature
    let publicKey: String  // Client public key (Base58 encoded)
    let challengeId: String  // Challenge ID
}

/// IP assignment packet
struct IpAssignPacket: Codable {
    let type = PacketType.ipAssign
    let ipAddress: String  // Assigned IP address
    let subnetMask: String  // Subnet mask
    let gateway: String  // Gateway address
    let dns: [String]  // DNS server addresses
    let encryptedSessionKey: String  // Base64 encoded encrypted session key
    let keyNonce: String  // Base64 encoded session key nonce
    let sessionId: String  // Session ID
    let leaseDuration: Int64  // Lease duration (seconds)
}

/// Data packet
struct DataPacket: Codable {
    let type = PacketType.data
    let encrypted: String  // Base64 encoded encrypted data
    let nonce: String  // Base64 encoded nonce
    let counter: Int64  // Packet counter
}

/// Error packet
struct ErrorPacket: Codable {
    let type = PacketType.error
    let code: Int
    let message: String
}

/// Disconnect packet
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
    
    // MARK: - Session Lifecycle
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting tunnel...", log: log, type: .info)
        
        // Initialize crypto manager
        cryptoManager = CryptoManager()
        
        // Start server handshake
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
        
        // Send disconnect message
        if let webSocketTask = webSocketTask, sessionId != nil {
            let disconnectPacket = DisconnectPacket(reason: "Client initiated disconnect")
            sendJsonPacket(disconnectPacket) { _ in
                // Continue cleanup regardless of send success
                self.cleanupResources()
                completionHandler()
            }
        } else {
            cleanupResources()
            completionHandler()
        }
    }
    
    private func cleanupResources() {
        // Stop packet processing
        isProcessingPackets = false
        
        // Close WebSocket connection
        webSocketTask?.cancel()
        webSocketTask = nil
        
        // Clean up resources
        sessionKey = nil
        serverPublicKey = nil
        sessionId = nil
        packetCounter = 0
        reconnectAttempts = 0
    }
    
    // MARK: - Server Handshake
    
    private func startServerHandshake(completion: @escaping (Error?) -> Void) {
        // 1. Connect to server
        guard let url = URL(string: "wss://your-vpn-server.com/connect") else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1000, userInfo: [NSLocalizedDescriptionKey: "Invalid server URL"]))
            return
        }
        
        guard let crypto = cryptoManager else {
            completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Crypto manager not initialized"]))
            return
        }
        
        // Load keypair
        let keypair: (privateKey: Data, publicKey: Data, publicKeyString: String)
        do {
            keypair = try crypto.loadKeypair()
        } catch {
            os_log("Failed to load keypair: %{public}@", log: log, type: .error, error.localizedDescription)
            completion(error)
            return
        }
        
        // Create WebSocket connection
        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        
        // 2. Send Auth packet
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
            
            // 3. Receive Challenge packet
            self.receiveJsonPacket { result in
                switch result {
                case .success(let packetData):
                    do {
                        // Parse as base packet to get type
                        let decoder = JSONDecoder()
                        let basePacket = try decoder.decode(BasePacket.self, from: packetData)
                        
                        switch basePacket.type {
                        case .challenge:
                            // Parse as full challenge packet
                            let challengePacket = try decoder.decode(ChallengePacket.self, from: packetData)
                            self.handleChallenge(challengePacket, privateKey: keypair.privateKey, completion: completion)
                        case .error:
                            let errorPacket = try decoder.decode(ErrorPacket.self, from: packetData)
                            let error = NSError(domain: "com.aeronyx.AeroNyx", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                            completion(error)
                        default:
                            let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1002, userInfo: [NSLocalizedDescriptionKey: "Expected Challenge packet, got \(basePacket.type.rawValue)"])
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
            // 1. Decode Base64 challenge data
            guard let challengeData = Data(base64Encoded: challengePacket.data) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1004, userInfo: [NSLocalizedDescriptionKey: "Invalid challenge data format"])
            }
            
            // 2. Decode Base58 server public key
            guard let serverPublicKeyData = Data(base58Encoded: challengePacket.serverKey) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1005, userInfo: [NSLocalizedDescriptionKey: "Invalid server key format"])
            }
            
            // Save server public key for later key derivation
            self.serverPublicKey = serverPublicKeyData
            
            // 3. Sign challenge data
            let signature = try crypto.sign(challenge: challengeData)
            
            // 4. Construct and send ChallengeResponse packet
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
                
                // 5. Receive IpAssign packet
                self.receiveJsonPacket { result in
                    switch result {
                    case .success(let packetData):
                        do {
                            // Parse as base packet to get type
                            let decoder = JSONDecoder()
                            let basePacket = try decoder.decode(BasePacket.self, from: packetData)
                            
                            switch basePacket.type {
                            case .ipAssign:
                                // Parse as full IP assign packet
                                let ipAssignPacket = try decoder.decode(IpAssignPacket.self, from: packetData)
                                self.handleIpAssign(ipAssignPacket, completion: completion)
                            case .error:
                                let errorPacket = try decoder.decode(ErrorPacket.self, from: packetData)
                                let error = NSError(domain: "com.aeronyx.AeroNyx", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                                completion(error)
                            default:
                                let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1006, userInfo: [NSLocalizedDescriptionKey: "Expected IpAssign packet, got \(basePacket.type.rawValue)"])
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
            // 1. Decode Base64 encrypted session key and nonce
            guard let encryptedSessionKeyData = Data(base64Encoded: ipAssignPacket.encryptedSessionKey),
                  let keyNonceData = Data(base64Encoded: ipAssignPacket.keyNonce) else {
                throw NSError(domain: "com.aeronyx.AeroNyx", code: 1008, userInfo: [NSLocalizedDescriptionKey: "Invalid session key format"])
            }
            
            // 2. Derive shared key
            let sharedSecret = try crypto.deriveSharedSecret(serverPublicKey: serverPublicKey)
            
            // 3. Decrypt session key
            self.sessionKey = try crypto.decryptSessionKey(
                encryptedKey: encryptedSessionKeyData,
                nonce: keyNonceData,
                sharedSecret: sharedSecret
            )
            
            // Save session ID
            self.sessionId = ipAssignPacket.sessionId
            
            // 4. Configure tunnel network settings
            let settings = createTunnelSettings(ipAssign: ipAssignPacket)
            
            setTunnelNetworkSettings(settings) { error in
                if let error = error {
                    os_log("Failed to set tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    completion(error)
                    return
                }
                
                // Handshake completed successfully
                os_log("Handshake completed successfully, tunnel configured", log: self.log, type: .info)
                completion(nil)
                
                // Start listening for server packets
                self.startReceivingPackets()
            }
        } catch {
            os_log("IP assign processing error: %{public}@", log: log, type: .error, error.localizedDescription)
            completion(error)
        }
    }
    
    private func createTunnelSettings(ipAssign: IpAssignPacket) -> NEPacketTunnelNetworkSettings {
            // Configure tunnel with server-provided information
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "your-vpn-server.com") // Actual VPN server address
            
            // Configure IPv4
            settings.ipv4Settings = NEIPv4Settings(
                addresses: [ipAssign.ipAddress],
                subnetMasks: [ipAssign.subnetMask]
            )
            
            if !ipAssign.gateway.isEmpty {
                settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
                settings.ipv4Settings?.excludedRoutes = [] // Optional, add based on server config
            }
            
            // Configure DNS
            if !ipAssign.dns.isEmpty {
                settings.dnsSettings = NEDNSSettings(servers: ipAssign.dns)
            }
            
            return settings
        }
        
        // MARK: - Packet Processing
        
        private func startPacketForwarding() {
            guard !isProcessingPackets else { return }
            isProcessingPackets = true
            
            // Start packet forwarding loop
            readPackets()
        }
        
        private func readPackets() {
            // Read packets from TUN interface
            packetFlow.readPackets { [weak self] packets, protocols in
                guard let self = self, self.isProcessingPackets else { return }
                
                self.socketQueue.async {
                    self.processAndSendPackets(packets, protocols: protocols)
                    // Continue reading more packets
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
                    // Continue receiving
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
                // Parse as base packet to get type
                let decoder = JSONDecoder()
                let basePacket = try decoder.decode(BasePacket.self, from: data)
                
                switch basePacket.type {
                case .data:
                    // Parse as data packet
                    let dataPacket = try decoder.decode(DataPacket.self, from: data)
                    handleDataPacket(dataPacket)
                case .ping:
                    // Respond to Ping
                    sendJsonPacket(BasePacket(type: .pong)) { error in
                        if let error = error {
                            os_log("Failed to send Pong: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        }
                    }
                case .error:
                    let errorPacket = try decoder.decode(ErrorPacket.self, from: data)
                    os_log("Received error packet: %{public}@", log: log, type: .error, errorPacket.message)
                case .disconnect:
                    let disconnectPacket = try decoder.decode(DisconnectPacket.self, from: data)
                    os_log("Received disconnect: %{public}@", log: log, type: .info, disconnectPacket.reason)
                    // Reconnect
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
                // Decode Base64 data
                guard let encryptedData = Data(base64Encoded: dataPacket.encrypted),
                      let nonceData = Data(base64Encoded: dataPacket.nonce) else {
                    throw NSError(domain: "com.aeronyx.AeroNyx", code: 1010, userInfo: [NSLocalizedDescriptionKey: "Invalid packet encoding"])
                }
                
                // Decrypt packet
                let decryptedData = try crypto.decryptPacket(encryptedData, nonce: nonceData, with: sessionKey)
                
                // Write to TUN interface
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
                    // Encrypt packet
                    let (encrypted, nonce) = try crypto.encryptPacket(packet, with: sessionKey)
                    
                    // Construct DataPacket structure
                    let dataPacket = DataPacket(
                        encrypted: encrypted.base64EncodedString(),
                        nonce: nonce.base64EncodedString(),
                        counter: OSAtomicIncrement64(&packetCounter)
                    )
                    
                    // Serialize and send
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
        
        // MARK: - WebSocket Helper Methods
        
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
            
            // Close current WebSocket
            webSocketTask?.cancel()
            webSocketTask = nil
            
            // Check reconnection count
            if reconnectAttempts >= maxReconnectAttempts {
                os_log("Maximum reconnection attempts reached (%d). Giving up.", log: log, type: .error, maxReconnectAttempts)
                // Clean up resources
                cleanupResources()
                return
            }
            
            reconnectAttempts += 1
            
            // Wait with delay before reconnecting
            let delay = Double(min(30, pow(2.0, Double(reconnectAttempts)))) // Exponential backoff
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self else { return }
                
                // Reset partial state
                self.sessionKey = nil
                self.serverPublicKey = nil
                self.packetCounter = 0
                
                // Restart handshake
                self.startServerHandshake { error in
                    if let error = error {
                        os_log("Reconnection failed: %{public}@", log: self.log, type: .error, error.localizedDescription)
                        self.handleConnectionError(error) // Recursive retry
                    } else {
                        os_log("Reconnection successful", log: self.log, type: .info)
                        self.reconnectAttempts = 0 // Reset reconnection counter
                        self.startPacketForwarding()
                    }
                }
            }
        }
        
        // MARK: - App Interaction
        
        override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
            do {
                guard let json = try JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                      let type = json["type"] as? String else {
                    completionHandler?(nil)
                    return
                }
                
                switch type {
                case "status":
                    // Return VPN status
                    let status: [String: Any] = [
                        "connected": (sessionKey != nil),
                        "sessionId": sessionId ?? "",
                        "assignedIp": getAssignedIp() ?? "Not Assigned"
                    ]
                    
                    if let responseData = try? JSONSerialization.data(withJSONObject: status, options: []) {
                        completionHandler?(responseData)
                    } else {
                        completionHandler?(nil)
                    }
                    
                case "disconnect":
                    // Manually disconnect
                    stopTunnel(with: .userInitiated) {
                        completionHandler?(nil)
                    }
                    
                case "ping":
                    // Send Ping to server
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
