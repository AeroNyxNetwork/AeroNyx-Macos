import NetworkExtension
import os.log
import Foundation
// Assumes you are using Module Map import (Recommended)
// If using dlopen/dlsym, you need the AeronyxCryptoLib class from before.
import AeronyxCryptoModule

// MARK: - Codable Packet Structs (Matching Rust Protocol)
// (These structs seem mostly okay, ensure field names match JSON exactly)

struct BasePacket: Codable {
    let type: String // Use String to match JSON, map to PacketType enum later
}

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
    // Add other types if needed (KeyRotation, IpRenewal etc.)
}

struct AuthPacket: Codable {
    let type = PacketType.auth.rawValue
    let publicKey: String // Base58 public key string
    let version: String // Client version string (e.g., "1.0.0")
    let features: [String] // Supported features (e.g., ["chacha20poly1305"])
    let nonce: String // Random nonce string

    enum CodingKeys: String, CodingKey {
        case type, publicKey = "public_key", version, features, nonce
    }
}

struct ChallengePacket: Codable {
    let type: String // Should be PacketType.challenge.rawValue
    let data: String // Base64 encoded challenge bytes
    let serverKey: String // Base58 encoded server public key
    let expiresAt: UInt64
    let id: String

    enum CodingKeys: String, CodingKey {
        case type, data, serverKey = "server_key", expiresAt = "expires_at", id
    }
}

struct ChallengeResponsePacket: Codable {
    let type = PacketType.challengeResponse.rawValue
    let signature: String // Base58 encoded signature string
    let publicKey: String // Base58 encoded client public key string
    let challengeId: String

    enum CodingKeys: String, CodingKey {
        case type, signature, publicKey = "public_key", challengeId = "challenge_id"
    }
}

struct IpAssignPacket: Codable {
    let type: String // Should be PacketType.ipAssign.rawValue
    let ipAddress: String
    let leaseDuration: UInt64
    let sessionId: String
    let encryptedSessionKey: String // Base64 encoded data
    let keyNonce: String // Base64 encoded data
    // Make these optional based on your actual server response
    let subnetMask: String? // Example: "255.255.255.0"
    let gateway: String?    // Example: Router IP on VPN subnet
    let dns: [String]?      // Example: ["8.8.8.8"]

    enum CodingKeys: String, CodingKey {
        case type, ipAddress = "ip_address", leaseDuration = "lease_duration"
        case sessionId = "session_id", encryptedSessionKey = "encrypted_session_key"
        case keyNonce = "key_nonce"
        case subnetMask, gateway, dns // Add if server sends them
    }
}

struct DataPacket: Codable {
    let type = PacketType.data.rawValue
    let encrypted: String // Base64 encoded data (Ciphertext + Tag)
    let nonce: String // Base64 encoded data
    let counter: Int64

    enum CodingKeys: String, CodingKey {
        case type, encrypted, nonce, counter
    }
}

struct ErrorPacket: Codable {
    let type: String // Should be PacketType.error.rawValue
    let code: Int    // Match the type used in server JSON if different
    let message: String
}

struct DisconnectPacket: Codable {
    let type = PacketType.disconnect.rawValue
    let reason: UInt16 // Match Rust type used in JSON if different
    let message: String
}

struct PingPacket: Codable {
    let type = PacketType.ping.rawValue
    let timestamp: UInt64
    let sequence: UInt64
}

struct PongPacket: Codable {
    let type = PacketType.pong.rawValue
    let echoTimestamp: UInt64
    let serverTimestamp: UInt64
    let sequence: UInt64

    enum CodingKeys: String, CodingKey {
         case type, echoTimestamp = "echo_timestamp", serverTimestamp = "server_timestamp", sequence
    }
}

// For handleAppMessage response
struct StatusResponse: Codable {
    let isConnected: Bool
    let vpnStatusRawValue: Int
    let vpnStatusDescription: String
    let sessionId: String
    let assignedIp: String
    let debugInfo: [String: String]? // Add debug information
}

// MARK: - PacketTunnelProvider Implementation

class PacketTunnelProvider: NEPacketTunnelProvider {
    // MARK: Properties
    private let log = OSLog(subsystem: Bundle.main.bundleIdentifier ?? "com.aeronyx.AeroNyx.PacketTunnel", category: "Provider")
    private var cryptoManager: CryptoManager?     // Holds our crypto logic instance
    private var sessionKey: Data?                 // Stores the derived session key
    private var webSocketTask: URLSessionWebSocketTask?
    private var serverPublicKey: Data?            // Store server's Ed25519 pubkey from Challenge
    private var sessionId: String?                // Store session ID from IpAssign
    private var assignedTunnelIP: String?         // Store assigned IP from IpAssign
    private var packetCounter: Int64 = 0          // Outgoing packet counter (needs proper atomic handling)
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5
    private var handshakeCompletion: ((Error?) -> Void)? // Store startTunnel completion handler
    private var isTunnelEstablished = false       // Tracks if tunnel setup (IP assign + setTunnelNetworkSettings) is complete
    private var isPacketProcessing = false       // Flag to control read/write loops
    private var lastError: Error?                // Store the last error for debugging

    // Queue for serializing WebSocket send/receive operations if needed
    private let socketQueue = DispatchQueue(label: "com.aeronyx.AeroNyx.SocketQueue", qos: .utility)


    // MARK: - Lifecycle Methods

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting tunnel...", log: log, type: .info)
        // Reset state for new connection attempt
        cleanupResources(sendDisconnect: false) // Clean up without sending disconnect
        isPacketProcessing = false
        isTunnelEstablished = false
        handshakeCompletion = completionHandler // Store completion handler
        lastError = nil // Clear previous errors

        // 1. Initialize CryptoManager
        do {
            cryptoManager = CryptoManager()
            // Ensure keypair is available before connecting
            _ = try cryptoManager?.loadKeypair()
             os_log("CryptoManager initialized and keypair loaded.", log: log, type: .debug)
        } catch {
            let errorDetails = getDetailedError(error)
            os_log("Failed to initialize CryptoManager or load keypair: %{public}@", log: self.log, type: .fault, errorDetails)
            lastError = error
            completionHandler(error) // Fail early
            return
        }

        // 2. Extract Server Address/Port from options
        guard let providerConfig = self.protocolConfiguration as? NETunnelProviderProtocol else {
            os_log("Invalid protocol configuration type", log: log, type: .fault)
            let configError = NSError(domain: "AeroNyx", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid protocol configuration type",
                "ConfigType": String(describing: type(of: self.protocolConfiguration))
            ])
            lastError = configError
            completionHandler(configError)
            return
        }
        
        guard let configDict = providerConfig.providerConfiguration else {
            os_log("Provider configuration is nil", log: log, type: .fault)
            let configError = NSError(domain: "AeroNyx", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Provider configuration is nil"
            ])
            lastError = configError
            completionHandler(configError)
            return
        }
        
        // Log available configuration keys for debugging
        os_log("Available config keys: %{public}@", log: log, type: .debug, configDict.keys.map { $0 })
        
        guard let serverAddress = configDict["ServerAddress"] as? String else {
            os_log("Missing ServerAddress in provider configuration", log: log, type: .fault)
            let configError = NSError(domain: "AeroNyx", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Missing server address",
                "AvailableKeys": configDict.keys.map { $0 }
            ])
            lastError = configError
            completionHandler(configError)
            return
        }
        
        guard let serverPort = configDict["ServerPort"] as? UInt16 else {
            os_log("Missing or invalid ServerPort in provider configuration", log: log, type: .fault)
            let portValue = configDict["ServerPort"]
            let portType = portValue != nil ? String(describing: type(of: portValue!)) : "nil"
            let configError = NSError(domain: "AeroNyx", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Missing or invalid server port",
                "ServerPortValue": portValue ?? "nil",
                "ServerPortType": portType
            ])
            lastError = configError
            completionHandler(configError)
            return
        }

        // Construct WebSocket URL (Assume root path unless specified otherwise)
        let urlString = "wss://\(serverAddress):\(serverPort)"
        guard let url = URL(string: urlString) else {
            os_log("Invalid server URL constructed: %{public}s", log: log, type: .fault, urlString)
            let urlError = NSError(domain: "AeroNyx", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Invalid server URL",
                "URL": urlString
            ])
            lastError = urlError
            completionHandler(urlError)
            return
        }

        os_log("Connecting to server: %{public}s", log: log, type: .info, urlString)

        // 3. Start WebSocket Connection & Handshake
        connectAndHandshake(url: url)
        // Completion handler is called within the handshake flow now
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel with reason: %{public}d", log: log, type: .info, reason.rawValue)
        // Pass the actual reason code if needed, map NEProviderStopReason appropriately
        let reasonCode = reason == .userInitiated ? 0 : 7 // Example mapping
        cleanupResources(sendDisconnect: true, reasonCode: UInt16(reasonCode), message: "Tunnel stopping: \(reason)")
        completionHandler()
    }

    // Centralized cleanup function
    private func cleanupResources(sendDisconnect: Bool = false, reasonCode: UInt16 = 7, message: String = "Disconnecting") {
        os_log("Cleaning up resources...", log: log, type: .debug)

        stopPacketProcessing() // Stop read/write loops first

        // Send disconnect message if requested and possible
        if sendDisconnect, let task = webSocketTask, task.closeCode == .invalid { // Check if socket might still be open
            let disconnectPacket = DisconnectPacket(reason: reasonCode, message: message)
            // Send synchronously or with short timeout as we are stopping
            sendJsonPacket(disconnectPacket, synchronous: true) { [weak self] error in
                if let error = error {
                    os_log("Failed to send disconnect packet: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription)
                }
                // Proceed with cleanup regardless of send success
                self?.cancelWebSocket()
            }
        } else {
            // Just cancel the socket directly
            cancelWebSocket()
        }

        // Reset state variables
        sessionKey = nil
        serverPublicKey = nil
        sessionId = nil
        assignedTunnelIP = nil
        packetCounter = 0 // Reset counter for next connection
        reconnectAttempts = 0
        isTunnelEstablished = false

        // cryptoManager = nil // Keep cryptoManager if needed? Depends on lifecycle.

        // Cancel pending completion handler if tunnel setup failed midway
        if let completion = handshakeCompletion {
            os_log("Cleanup called before tunnel fully established, calling completion handler with error.", log: log, type: .info)
            handshakeCompletion = nil // Prevent calling multiple times
            let cleanupError = NSError(domain: "AeroNyx", code: 99, userInfo: [NSLocalizedDescriptionKey: message])
            lastError = cleanupError
            completion(cleanupError)
        }
        os_log("Resources cleaned up.", log: log, type: .info)
    }

    private func cancelWebSocket() {
         guard webSocketTask != nil else { return }
         os_log("Cancelling WebSocket task.", log: log, type: .debug)
         webSocketTask?.cancel(with: .normalClosure, reason: nil)
         webSocketTask = nil
    }

    // MARK: - Handshake Logic (Corrected Protocol Flow)

    private func connectAndHandshake(url: URL) {
        guard let crypto = cryptoManager else {
            let error = NSError(domain: "AeroNyx", code: 1001, userInfo: [NSLocalizedDescriptionKey: "Crypto manager not initialized"])
            lastError = error
            handleHandshakeError(error)
            return
        }

        let keypair: (privateKey: Data, publicKey: Data, publicKeyString: String)
        do {
            keypair = try crypto.loadKeypair()
        } catch {
            os_log("Failed to load keypair for handshake: %{public}@", log: log, type: .error, error.localizedDescription)
            lastError = error
            handleHandshakeError(error)
            return
        }

        // Create WebSocket Task
        // Use a background queue for delegate methods if needed, or rely on URLSession's internal queues
        let session = URLSession(configuration: .default, delegate: nil, delegateQueue: OperationQueue())
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()

        // Start receiving loop immediately after resume
        startReceivingMessages()

        // Send Auth packet shortly after resuming (allowing connection setup)
        socketQueue.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self = self, self.webSocketTask != nil else { return }

            // --- PROTOCOL FIX 1: Send Auth Packet (JSON + Base64) ---
            let authPacket = AuthPacket(
                publicKey: keypair.publicKeyString, // Base58 String
                version: "client-swift-1.0",        // Example version
                features: ["chacha20poly1305"],     // Features client supports
                nonce: UUID().uuidString            // Example random nonce String
            )

            os_log("Sending Auth packet...", log: self.log, type: .debug)
            self.sendJsonPacket(authPacket) { error in // sendJsonPacket handles JSON + String send
                if let error = error {
                    os_log("Failed to send Auth packet: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    self.lastError = error
                    // Don't fail entire handshake here, let receive loop handle errors
                } else {
                    os_log("Auth packet sent successfully. Waiting for Challenge...", log: self.log, type: .debug)
                }
            }
            // Now wait for Challenge via the receive loop (startReceivingMessages)
        }
    }

    // Process Challenge Packet
    private func processChallengePacket(_ challengePacket: ChallengePacket) {
        os_log("Processing Challenge packet ID: %{public}s", log: log, type: .debug, challengePacket.id)
        guard let crypto = cryptoManager else {
             let error = NSError(domain: "AeroNyx", code: 1003, userInfo: [NSLocalizedDescriptionKey: "Crypto manager not initialized"])
             lastError = error
             handleHandshakeError(error)
             return
        }

        do {
            // --- PROTOCOL FIX 2: Decode Base64/Base58 fields ---
            guard let challengeData = Data(base64Encoded: challengePacket.data) else {
                let error = NSError(domain: "AeroNyx", code: 1004, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 challenge data"])
                lastError = error
                throw error
            }
            guard let serverPublicKeyData = Data(base58Encoded: challengePacket.serverKey) else { // Server key is Base58
                let error = NSError(domain: "AeroNyx", code: 1005, userInfo: [NSLocalizedDescriptionKey: "Invalid Base58 server key"])
                lastError = error
                throw error
            }
            self.serverPublicKey = serverPublicKeyData // Store for later ECDH

            // Sign the *decoded* challenge data
            let keypair = try crypto.loadKeypair()
            let signatureData = try AeronyxCrypto.signEd25519(privateKey: keypair.privateKey, message: challengeData)

            // Base58 encode the signature *for the JSON packet*
            let signatureBase58 = signatureData.base58EncodedString // Assumes working Base58 extension

            // --- PROTOCOL FIX 3: Send ChallengeResponse Packet (JSON + Base64/Base58) ---
            let responsePacket = ChallengeResponsePacket(
                signature: signatureBase58,            // Base58 signature
                publicKey: keypair.publicKeyString,    // Base58 client public key
                challengeId: challengePacket.id       // Echo the challenge ID
            )

            os_log("Sending ChallengeResponse packet...", log: log, type: .debug)
            sendJsonPacket(responsePacket) { error in // sendJsonPacket handles JSON + String send
                 if let error = error {
                      os_log("Failed to send ChallengeResponse: %{public}@", log: self.log, type: .error, error.localizedDescription)
                      self.lastError = error
                      // Let receive loop handle server disconnect/error
                 } else {
                      os_log("ChallengeResponse sent successfully. Waiting for IpAssign...", log: self.log, type: .debug)
                 }
            }
            // Now wait for IpAssign via the receive loop (startReceivingMessages)

        } catch {
            os_log("Challenge processing error: %{public}@", log: log, type: .error, error.localizedDescription)
            lastError = error
            handleHandshakeError(error)
        }
    }

    // Process IP Assign Packet
    private func processIpAssignPacket(_ ipAssignPacket: IpAssignPacket) {
        os_log("Processing IpAssign packet for session: %{public}s", log: log, type: .debug, ipAssignPacket.sessionId)
        guard let crypto = cryptoManager, let serverPublicKeyData = self.serverPublicKey else {
             let error = NSError(domain: "AeroNyx", code: 1007, userInfo: [NSLocalizedDescriptionKey: "Crypto manager or server public key missing for IpAssign"])
             lastError = error
             handleHandshakeError(error)
             return
        }

        do {
            // --- PROTOCOL FIX 4: Decode Base64 Session Key and Nonce ---
            guard let encryptedKeyData = Data(base64Encoded: ipAssignPacket.encryptedSessionKey),
                  let keyNonceData = Data(base64Encoded: ipAssignPacket.keyNonce) else {
                let error = NSError(domain: "AeroNyx", code: 1008, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 session key or nonce"])
                lastError = error
                throw error
            }

            // Derive shared secret (using stored server key)
            let sharedSecret = try crypto.deriveSharedSecret(serverPublicKey: serverPublicKeyData)

            // Decrypt session key using FFI
            self.sessionKey = try AeronyxCrypto.decryptChaCha20Poly1305(
                ciphertext: encryptedKeyData, // Pass combined Ciphertext+Tag
                key: sharedSecret,
                nonce: keyNonceData
            )

            // Store session ID and assigned IP
            self.sessionId = ipAssignPacket.sessionId
            self.assignedTunnelIP = ipAssignPacket.ipAddress // Store the assigned IP

            os_log("Session key successfully decrypted and stored.", log: log, type: .info)

            // --- PROTOCOL FIX 5: Configure Tunnel Network Settings *NOW* ---
            guard let serverAddressFromConfig = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["ServerAddress"] as? String else {
                  let error = NSError(domain: "AeroNyx", code: 1018, userInfo: [NSLocalizedDescriptionKey: "Cannot retrieve server address from configuration for tunnel settings"])
                  lastError = error
                  throw error
             }
            let settings = createTunnelSettings(ipAssign: ipAssignPacket, remoteAddress: serverAddressFromConfig)

            os_log("Setting tunnel network settings...", log: log, type: .debug)
            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self = self else { return }
                if let error = error {
                    os_log("Failed to set tunnel network settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                    self.lastError = error
                    self.handleHandshakeError(error) // Use handshake error handler
                    return
                }

                // Handshake and Tunnel Setup Complete!
                os_log("Tunnel network settings applied. Handshake complete.", log: self.log, type: .info)
                self.isTunnelEstablished = true
                self.reconnectAttempts = 0 // Reset reconnect attempts on success

                // Call original startTunnel completion handler ONLY ONCE
                if let completion = self.handshakeCompletion {
                     self.handshakeCompletion = nil // Clear handler
                     completion(nil) // Signal success
                }

                // Start forwarding packets
                self.startPacketForwarding()
            }

        } catch {
            os_log("IpAssign processing error: %{public}@", log: log, type: .error, error.localizedDescription)
            lastError = error
            handleHandshakeError(error)
        }
    }

    // Unified error handling during handshake - Calls completion handler
    private func handleHandshakeError(_ error: Error) {
         let errorDetails = getDetailedError(error)
         os_log("Handshake Error: %{public}@", log: log, type: .error, errorDetails)
         cleanupResources() // Clean up on any handshake error
         // Call the stored completion handler with the error
         if let completion = handshakeCompletion {
              handshakeCompletion = nil // Clear handler
              completion(error)
         }
    }

    // MARK: - Tunnel Configuration

    // Modified to take IpAssign packet and the actual remote address
    private func createTunnelSettings(ipAssign: IpAssignPacket, remoteAddress: String) -> NEPacketTunnelNetworkSettings {
         os_log("Creating tunnel settings with IP: %{public}s", log: log, type: .debug, ipAssign.ipAddress)
         // Use the actual server address as the tunnel remote address
         let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

         // Configure IPv4 using details from server
         // Use provided subnet mask or a default if necessary
         let subnetMask = ipAssign.subnetMask ?? "255.255.255.0" // Default if server doesn't send
         let ipv4Settings = NEIPv4Settings(addresses: [ipAssign.ipAddress], subnetMasks: [subnetMask])

         // Route all traffic through the tunnel by default
         ipv4Settings.includedRoutes = [NEIPv4Route.default()]
         // Exclude local network? Add based on server config if needed
         // ipv4Settings.excludedRoutes = [NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")]

         settings.ipv4Settings = ipv4Settings

         // Configure DNS using details from server or fallback
         let dnsServers = ipAssign.dns ?? ["8.8.8.8", "8.8.4.4"] // Use server DNS or fallback
         if !dnsServers.isEmpty {
             settings.dnsSettings = NEDNSSettings(servers: dnsServers)
             // Optional: Add match domains if needed
             // settings.dnsSettings?.matchDomains = ["internal.company.com"]
             // settings.dnsSettings?.matchDomainsNoSearch = true // Usually true for VPN DNS
         }

         // Set MTU if needed (consult server configuration/defaults)
          // let mtu = 1400 // Example MTU
          // settings.mtu = NSNumber(value: mtu)
          // os_log("Setting MTU to %d", log: log, type: .debug, mtu)

         return settings
    }

    // MARK: - Data Forwarding

    private func startPacketForwarding() {
        guard isTunnelEstablished && !isPacketProcessing else {
             if !isTunnelEstablished { os_log("Cannot start forwarding, tunnel not established.", log: log, type: .default) } // Changed to default
             if isPacketProcessing { os_log("Packet forwarding loop already running.", log: log, type: .debug)}
             return
        }
        os_log("Starting packet forwarding loops.", log: log, type: .info)
        isPacketProcessing = true
        readPacketsFromTunnel() // Start reading from TUN
        // Receiving from WebSocket is handled by startReceivingMessages loop
    }

    private func stopPacketProcessing() { // Renamed for clarity
        if isPacketProcessing {
             os_log("Stopping packet processing loops.", log: log, type: .info)
             isPacketProcessing = false // Signal loops to stop
             // The readPacketsFromTunnel loop checks this flag
             // The startReceivingMessages loop also implicitly stops via WebSocket closure/error
        }
    }


    // Read IP packets from the virtual TUN interface
    private func readPacketsFromTunnel() {
        // Use 'packetFlow' directly, assuming it's valid when tunnel is established
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isPacketProcessing else { // Use self. prefix
                os_log("TUN Read: Loop stopping (isPacketProcessing is false or self is nil).", log: self?.log ?? .default, type: .debug)
                return
            }

            // Process packets on the socket queue
            self.socketQueue.async { // Use self. prefix
                self.processAndSendPackets(packets, protocols: protocols) // Use self. prefix
            }

            // Schedule the next read recursively ONLY if still processing
            // Add small delay to prevent potential CPU spin if readPackets completes immediately
             DispatchQueue.main.asyncAfter(deadline: .now() + 0.001) { [weak self] in
                   guard let self = self, self.isPacketProcessing else { return }
                   self.readPacketsFromTunnel() // Use self. prefix
             }
        }
    }

    // Encrypt and send IP packets to the WebSocket server
    private func processAndSendPackets(_ packets: [Data], protocols: [NSNumber]) {
        guard let sessionKey = self.sessionKey, // Use self. prefix
              let crypto = self.cryptoManager, // Use self. prefix
              let webSocketTask = self.webSocketTask, // Use self. prefix
              !packets.isEmpty else {
            os_log("Cannot send packets, missing session key, crypto, socket, or empty packet list.", log: log, type: .default) // Changed to default
            return
        }

        for packet in packets {
             guard packet.count < (16 * 1024) else { // Example limit (16KB) - adjust as needed
                  os_log("Dropping oversized packet from TUN: %d bytes", log: log, type: .default, packet.count) // Changed to default
                  continue
             }

            do {
                // Encrypt using FFI wrapper
                let (encryptedPayload, nonce) = try crypto.encryptPacket(packet, with: sessionKey)

                // Increment counter atomically (replace with proper atomic operation)
                 // OSAtomicIncrement64(&packetCounter) // Deprecated, use NSLock or Atomics
                 // Simple non-atomic increment for now:
                 self.packetCounter += 1 // Use self. prefix
                 let currentCounter = self.packetCounter // Use self. prefix

                // --- PROTOCOL FIX 6: Create DataPacket struct with Base64 ---
                let dataPacket = DataPacket(
                    encrypted: encryptedPayload.base64EncodedString(), // Base64 encode
                    nonce: nonce.base64EncodedString(),               // Base64 encode
                    counter: currentCounter
                )

                // Serialize and send as JSON string
                // Use self. prefix for log
                sendJsonPacket(dataPacket) { [weak self] error in // Use self. prefix
                    if let error = error {
                        os_log("Failed to send Data packet: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription) // Use self?.log
                        self?.lastError = error
                        // Consider connection error handling
                    } else {
                        os_log("Sent Data packet, counter: %lld", log: self?.log ?? .default, type: .debug, currentCounter) // Use self?.log
                    }
                }
            } catch {
                os_log("Failed to encrypt packet: %{public}@", log: log, type: .error, error.localizedDescription)
                lastError = error
            }
        }
    }

    // MARK: - WebSocket Receive Logic

    // Start the loop for receiving messages from WebSocket
    private func startReceivingMessages() {
         guard let task = webSocketTask else {
              os_log("Cannot start receiving messages, WebSocket task is nil.", log: log, type: .error)
              // If handshake was in progress, fail it
               if let completion = handshakeCompletion {
                    handshakeCompletion = nil
                    let error = NSError(domain: "AeroNyx", code: 1021, userInfo: [NSLocalizedDescriptionKey: "WebSocket task not available for receive"])
                    lastError = error
                    completion(error)
               }
              return
         }

         os_log("Starting WebSocket receive loop.", log: log, type: .debug)
         task.receive { [weak self] result in
              guard let self = self else { return }

              switch result {
              case .success(let message):
                   self.handleWebSocketMessage(message)
                   // Schedule next receive *only if* websocket is still valid
                   // and we are processing packets OR handshake isn't finished
                   if self.webSocketTask != nil && (self.isPacketProcessing || !self.isTunnelEstablished) {
                        self.startReceivingMessages() // Recursive call for next message
                   } else {
                        os_log("WebSocket receive loop ending (task nil or state stopped).", log: self.log, type: .debug)
                   }
              case .failure(let error):
                   os_log("WebSocket receive error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                   self.lastError = error
                   // Handle connection error (might trigger reconnect)
                   // Only reconnect if tunnel was established OR handshake was still in progress
                   if self.isTunnelEstablished || self.handshakeCompletion != nil {
                        self.handleConnectionError(error)
                   } else {
                        // Error happened before handshake completed and no completion handler left
                        os_log("WebSocket error before tunnel setup complete, not auto-reconnecting.", log: self.log, type: .info)
                        self.cleanupResources() // Ensure cleanup if something failed early
                   }
              }
         }
    }

    // Process raw WebSocket messages
    private func handleWebSocketMessage(_ message: URLSessionWebSocketTask.Message) {
        // Use the dedicated socket queue to process messages serially
        socketQueue.async { [weak self] in
             guard let self = self else { return }
             os_log("Received WebSocket message.", log: self.log, type: .debug)
             var packetData: Data? = nil
             switch message {
             case .data(let data):
                 // Server sends JSON strings, but handle data just in case
                 packetData = data
                 os_log("Received WebSocket binary data (%d bytes) - expected JSON string.", log: self.log, type: .default, data.count) // Changed to default
                 
                 // Try to convert binary data to string for debugging
                 if let dataString = String(data: data, encoding: .utf8) {
                     os_log("Binary data as string: %{public}@", log: self.log, type: .debug, dataString)
                 }
                 
             case .string(let string):
                 // This is the expected path
                 packetData = string.data(using: .utf8)
                 os_log("Received WebSocket string message (%d characters)", log: self.log, type: .debug, string.count)
                                  if string.count < 1000 { // Only log shorter strings to avoid oversized logs
                                      os_log("WebSocket string content: %{public}@", log: self.log, type: .debug, string)
                                  } else {
                                      os_log("WebSocket string content too large, first 100 chars: %{public}@", log: self.log, type: .debug, String(string.prefix(100)))
                                  }
                                  
                              @unknown default:
                                  os_log("Unknown WebSocket message type received.", log: self.log, type: .default) // Changed to default
                                  return // Ignore unknown types
                              }

                              guard let data = packetData else {
                                   os_log("Failed to get data from WebSocket message.", log: self.log, type: .error)
                                   return
                              }

                              // Process based on state (Handshake vs Data Transfer)
                              if !self.isTunnelEstablished {
                                   // Currently in Handshake phase
                                   self.processHandshakeResponse(data)
                              } else {
                                   // In Data Transfer phase
                                   self.processDataOrControlPacket(data)
                              }
                         }
                     }

                     // Process messages received *during* the handshake phase
                     private func processHandshakeResponse(_ data: Data) {
                          // Ensure completion handler is still valid
                          guard let completion = self.handshakeCompletion else {
                               os_log("Received handshake response but no completion handler stored (likely already completed or failed).", log: log, type: .default) // Changed to default
                               return
                          }

                          do {
                              let decoder = JSONDecoder()
                              // Use base packet to check type first
                              let basePacket = try decoder.decode(BasePacket.self, from: data)
                              // Map string type to enum
                              guard let packetType = PacketType(rawValue: basePacket.type) else {
                                    let error = NSError(domain: "AeroNyx", code: 1025, userInfo: [NSLocalizedDescriptionKey: "Unknown packet type string received: \(basePacket.type)"])
                                    lastError = error
                                    throw error
                              }

                              os_log("Processing handshake response type: %{public}s", log: log, type: .debug, basePacket.type)

                              switch packetType {
                              case .challenge:
                                   let challengePacket = try decoder.decode(ChallengePacket.self, from: data)
                                   processChallengePacket(challengePacket)
                              case .ipAssign:
                                   let ipAssignPacket = try decoder.decode(IpAssignPacket.self, from: data)
                                   processIpAssignPacket(ipAssignPacket)
                              case .error:
                                   let errorPacket = try decoder.decode(ErrorPacket.self, from: data)
                                   os_log("Received error during handshake: [%d] %{public}s", log: self.log, type: .error, errorPacket.code, errorPacket.message)
                                   let error = NSError(domain: "AeroNyxServer", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                                   lastError = error
                                   handleHandshakeError(error) // Let handler call completion
                              default:
                                   let error = NSError(domain: "AeroNyx", code: 1019, userInfo: [NSLocalizedDescriptionKey: "Unexpected packet type during handshake: \(basePacket.type)"])
                                   lastError = error
                                   handleHandshakeError(error)
                              }
                          } catch {
                               os_log("Failed to parse handshake response: %{public}@", log: log, type: .error, error.localizedDescription)
                               lastError = error
                               handleHandshakeError(error)
                          }
                     }

                     // Process messages received *after* the tunnel is established
                     private func processDataOrControlPacket(_ data: Data) {
                          guard self.isTunnelEstablished else {
                               os_log("Received packet but tunnel not established, ignoring.", log: log, type: .default) // Changed to default
                               return
                          }

                          do {
                              let decoder = JSONDecoder()
                              let basePacket = try decoder.decode(BasePacket.self, from: data)
                              guard let packetType = PacketType(rawValue: basePacket.type) else {
                                   let error = NSError(domain: "AeroNyx", code: 1025, userInfo: [NSLocalizedDescriptionKey: "Unknown packet type string received: \(basePacket.type)"])
                                   lastError = error
                                   throw error
                              }
                              os_log("Processing post-handshake packet type: %{public}s", log: log, type: .debug, basePacket.type)

                              switch packetType {
                              case .data:
                                  let dataPacket = try decoder.decode(DataPacket.self, from: data)
                                  handleDataPacket(dataPacket)
                              case .ping:
                                   let pingPacket = try decoder.decode(PingPacket.self, from: data)
                                   os_log("Received Ping (seq: %lld), sending Pong.", log: log, type: .debug, pingPacket.sequence)
                                   let pongPacket = PongPacket(
                                        echoTimestamp: pingPacket.timestamp,
                                        serverTimestamp: UInt64(Date().timeIntervalSince1970 * 1000), // Current ms
                                        sequence: pingPacket.sequence
                                   )
                                   // Use background queue for sending
                                   sendJsonPacket(pongPacket) { [weak self] error in
                                        if let error = error {
                                             os_log("Failed to send Pong: %{public}@", log: self?.log ?? .default, type: .error, error.localizedDescription)
                                             self?.lastError = error
                                        }
                                   }
                              case .disconnect:
                                  let disconnectPacket = try decoder.decode(DisconnectPacket.self, from: data)
                                  os_log("Received disconnect from server: [%d] %{public}s", log: log, type: .info, disconnectPacket.reason, disconnectPacket.message)
                                  let error = NSError(domain: "AeroNyxServer", code: Int(disconnectPacket.reason), userInfo: [NSLocalizedDescriptionKey: "Server disconnected: \(disconnectPacket.message)"])
                                  lastError = error
                                  // Trigger reconnect logic
                                  handleConnectionError(error)
                              case .error:
                                   let errorPacket = try decoder.decode(ErrorPacket.self, from: data)
                                   os_log("Received error from server: [%d] %{public}s", log: self.log, type: .error, errorPacket.code, errorPacket.message)
                                   let error = NSError(domain: "AeroNyxServer", code: errorPacket.code, userInfo: [NSLocalizedDescriptionKey: errorPacket.message])
                                   lastError = error
                                   // Trigger reconnect logic (or specific handling)
                                   handleConnectionError(error)
                              // Handle KeyRotation, IpRenewalResponse etc. if needed
                              default:
                                  os_log("Unexpected packet type after handshake: %{public}@", log: log, type: .default, basePacket.type) // Changed to default
                              }
                          } catch {
                              os_log("Failed to parse post-handshake packet: %{public}@", log: log, type: .error, error.localizedDescription)
                              lastError = error
                          }
                     }

                     // Decrypt and write packet data to TUN interface
                        private func handleDataPacket(_ dataPacket: DataPacket) {
                            guard let sessionKey = self.sessionKey,
                                  let crypto = self.cryptoManager else {
                                os_log("Cannot process Data packet: missing session key or crypto manager", log: log, type: .error)
                                return
                            }
                            os_log("Received Data packet, counter: %lld", log: log, type: .debug, dataPacket.counter)
                            // TODO: Implement replay protection using dataPacket.counter

                            do {
                                // --- PROTOCOL FIX 7: Decode Base64 payload and nonce ---
                                guard let encryptedData = Data(base64Encoded: dataPacket.encrypted),
                                      let nonceData = Data(base64Encoded: dataPacket.nonce) else {
                                    let error = NSError(domain: "AeroNyx", code: 1010, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encoding in Data packet"])
                                    lastError = error
                                    throw error
                                }

                                // Decrypt using FFI wrapper
                                let decryptedData = try crypto.decryptPacket(encryptedData, nonce: nonceData, with: sessionKey)

                                // Write decrypted IP packet to TUN interface
                                guard !decryptedData.isEmpty else {
                                    os_log("Decryption resulted in empty data, skipping write.", log: log, type: .default)
                                    return
                                }
                                os_log("Writing %d bytes to tunnel interface.", log: log, type: .debug, decryptedData.count)
                                self.packetFlow.writePackets([decryptedData], withProtocols: [NSNumber(value: AF_INET)]) // AF_INET for IPv4

                            } catch {
                                // Handle all errors the same way
                                os_log("Failed to process Data packet: %{public}@", log: log, type: .error, error.localizedDescription)
                                lastError = error
                                
                                // Log additional info if this is a crypto error
                                if let nsError = error as? NSError, nsError.domain == "AeronyxCrypto" {
                                    os_log("This appears to be a crypto error", log: log, type: .error)
                                }
                            }
                        }

                     // MARK: - WebSocket Send/Receive Helpers

                     // Added synchronous option for sending disconnect on stop
                     private func sendJsonPacket<T: Encodable>(_ packet: T, synchronous: Bool = false, completion: @escaping (Error?) -> Void) {
                         guard let task = webSocketTask else {
                             let error = NSError(domain: "AeroNyx", code: 1020, userInfo: [NSLocalizedDescriptionKey: "WebSocket task not available for send"])
                             lastError = error
                             completion(error)
                             return
                         }

                         let operation = { [weak self] in // Use weak self inside block
                              guard let self = self else {
                                   let error = NSError(domain: "AeroNyx", code: 1027, userInfo: [NSLocalizedDescriptionKey: "Self deallocated before send"])
                                   completion(error)
                                   return
                              }
                              do {
                                  let encoder = JSONEncoder()
                                  let jsonData = try encoder.encode(packet)

                                  guard let jsonString = String(data: jsonData, encoding: .utf8) else {
                                      let error = NSError(domain: "AeroNyx", code: 1013, userInfo: [NSLocalizedDescriptionKey: "Failed to encode JSON as UTF8 string"])
                                      self.lastError = error
                                      throw error
                                  }

                                  os_log("Sending WebSocket message: %{public}s", log: self.log, type: .debug, jsonString)
                                  task.send(.string(jsonString)) { error in
                                       // Completion handler called on URLSession's queue, dispatch if UI update needed
                                       // For internal logic, maybe stay off main thread?
                                        if let error = error {
                                            self.lastError = error
                                        }
                                        completion(error) // Call completion directly
                                  }
                              } catch {
                                   os_log("JSON serialization error: %{public}@", log: self.log, type: .error, error.localizedDescription)
                                   self.lastError = error
                                   completion(error) // Call completion with error
                              }
                         }

                         if synchronous {
                              socketQueue.sync(execute: operation) // Execute synchronously on queue
                         } else {
                              socketQueue.async(execute: operation) // Execute asynchronously on queue
                         }
                     }

                     // Wrapper to ensure receive completion is handled on our socketQueue
                     private func receiveWebSocketMessage(completion: @escaping (Result<URLSessionWebSocketTask.Message, Error>) -> Void) {
                         guard let task = webSocketTask else {
                             let error = NSError(domain: "AeroNyx", code: 1021, userInfo: [NSLocalizedDescriptionKey: "WebSocket task not available for receive"])
                             lastError = error
                             socketQueue.async { // Dispatch error callback onto queue too
                                  completion(.failure(error))
                             }
                             return
                         }

                         task.receive { [weak self] result in
                             // Result is likely on URLSession's delegate queue, dispatch to our queue
                             if case .failure(let error) = result {
                                 self?.lastError = error
                             }
                             self?.socketQueue.async { // Dispatch result callback onto queue
                                  completion(result)
                             }
                         }
                     }

                     // Helper to get detailed error information
                     private func getDetailedError(_ error: Error) -> String {
                         var details = error.localizedDescription
                         
                         // Try to get more detailed error information
                         if let nsError = lastError as? NSError {
                             details += " (Code: \(nsError.code), Domain: \(nsError.domain)"
                             
                             if let failureReason = nsError.localizedFailureReason {
                                 details += ", Reason: \(failureReason)"
                             }
                             
                             // Add extra error information if available
                             if let userInfo = nsError.userInfo as? [String: Any], !userInfo.isEmpty {
                                 let userInfoString = userInfo.compactMap { key, value -> String? in
                                     guard key != NSLocalizedDescriptionKey,
                                           key != NSLocalizedFailureReasonErrorKey,
                                           key != NSLocalizedRecoverySuggestionErrorKey,
                                           key != NSLocalizedRecoveryOptionsErrorKey else {
                                         return nil
                                     }
                                     return "\(key): \(value)"
                                 }.joined(separator: ", ")
                                 
                                 if !userInfoString.isEmpty {
                                     details += ", Details: \(userInfoString)"
                                 }
                             }
                             
                             details += ")"
                         }
                         
                         return details
                     }

                     // MARK: - Reconnection Logic

                      private func handleConnectionError(_ error: Error) {
                           let errorDetails = getDetailedError(error)
                           
                           // Avoid reconnect loops if tunnel is already stopping/stopped
                           guard isPacketProcessing || handshakeCompletion != nil else {
                                os_log("Connection error occurred but tunnel is stopping/stopped. Ignoring: %{public}@", log: log, type: .info, errorDetails)
                                // If handshakeCompletion exists, it means we failed during startup, so call it.
                                 if let completion = handshakeCompletion {
                                      handshakeCompletion = nil // Prevent multiple calls
                                      completion(error)
                                 }
                                return
                           }

                          os_log("Connection error, attempting reconnect: %{public}@", log: log, type: .error, errorDetails)

                          // Immediately clean up current connection state
                          cancelWebSocket() // Ensure socket is closed
                          isTunnelEstablished = false // Mark as not established
                          isPacketProcessing = false // Stop packet processing loops explicitly
                          sessionKey = nil
                          serverPublicKey = nil
                          // Keep cryptoManager

                          // Check reconnect attempts
                          if reconnectAttempts >= maxReconnectAttempts {
                              os_log("Maximum reconnection attempts reached (%d). Stopping tunnel.", log: log, type: .fault, maxReconnectAttempts)
                               let finalError = NSError(domain: "AeroNyx", code: 1022, userInfo: [
                                   NSLocalizedDescriptionKey: "Max reconnection attempts reached: \(error.localizedDescription)",
                                   "MaxAttempts": maxReconnectAttempts,
                                   "CurrentAttempt": reconnectAttempts,
                                   "OriginalError": error.localizedDescription
                               ])
                               lastError = finalError
                               // If handshake was in progress, call its completion handler
                               if let completion = handshakeCompletion {
                                    handshakeCompletion = nil
                                    completion(finalError)
                               } else {
                                    // If tunnel was already running, use cancelTunnelWithError
                                    cancelTunnelWithError(finalError)
                               }
                              cleanupResources() // Perform final cleanup
                              return
                          }

                          reconnectAttempts += 1

                          // Calculate exponential backoff delay
                          let delay = min(30.0, pow(2.0, Double(reconnectAttempts))) // Max 30 seconds
                          os_log("Waiting %.1f seconds before reconnect attempt #%d...", log: log, type: .info, delay, reconnectAttempts)

                          // Schedule reconnect on the main queue to avoid blocking socket queue
                          DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                              guard let self = self else { return }
                               // Check if tunnel was stopped manually during the delay
                               // Need a reliable way to check OS state or internal desired state
                               guard self.handshakeCompletion != nil || self.isPacketProcessing else { // Check if we are still supposed to be running/connecting
                                    os_log("Tunnel stopped during reconnect delay.", log: self.log, type: .info)
                                    return
                               }

                               os_log("Attempting reconnect #%d...", log: self.log, type: .info, self.reconnectAttempts)
                              // Retrieve config and restart handshake
                               guard let providerConfig = self.protocolConfiguration as? NETunnelProviderProtocol,
                                     let configDict = providerConfig.providerConfiguration,
                                     let serverAddress = configDict["ServerAddress"] as? String,
                                     let serverPort = configDict["ServerPort"] as? UInt16 else {
                                   os_log("Cannot reconnect, missing server configuration.", log: self.log, type: .fault)
                                   let configError = NSError(domain: "AeroNyx", code: 1023, userInfo: [
                                       NSLocalizedDescriptionKey: "Cannot reconnect, missing server configuration."
                                       // Remove the problematic line referring to providerConfig
                                   ])
                                   self.lastError = configError
                                   // If handshake was in progress, call its completion
                                    if let completion = self.handshakeCompletion {
                                        self.handshakeCompletion = nil
                                        completion(configError)
                                    } else {
                                        self.cancelTunnelWithError(configError)
                                    }
                                   self.cleanupResources()
                                   return
                               }
                               let urlString = "wss://\(serverAddress):\(serverPort)"
                               guard let url = URL(string: urlString) else {
                                    os_log("Cannot reconnect, invalid server URL: %{public}s", log: self.log, type: .fault, urlString)
                                    let urlError = NSError(domain: "AeroNyx", code: 1024, userInfo: [
                                        NSLocalizedDescriptionKey: "Invalid server URL for reconnect.",
                                        "URL": urlString
                                    ])
                                    self.lastError = urlError
                                    if let completion = self.handshakeCompletion {
                                        self.handshakeCompletion = nil
                                        completion(urlError)
                                    } else {
                                        self.cancelTunnelWithError(urlError)
                                    }
                                   self.cleanupResources()
                                    return
                               }

                               // Restart handshake. If initial startTunnel failed, use its completion handler.
                               self.connectAndHandshake(url: url)
                          }
                      }


                     // MARK: - App Message Handling

                    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil ) {
                        os_log("Handling app message...", log: log, type: .debug)
                        let responseHandler = completionHandler ?? { _ in } // Ensure handler is non-nil

                        // Decode the message (example: expecting JSON dictionary)
                        do {
                            let message = try JSONDecoder().decode([String: String].self, from: messageData)
                            
                            guard let type = message["type"] else {
                                let error = NSError(domain: "AeroNyx", code: 2001, userInfo: [
                                    NSLocalizedDescriptionKey: "Missing type field in message",
                                    "AvailableKeys": message.keys.map { $0 }
                                ])
                                throw error
                            }
                            
                            os_log("Received app message type: %{public}s", log: log, type: .info, type)

                            switch type {
                            case "getStatus":
                                // Create detailed status response using internal state
                                let isSessionReady = (self.sessionKey != nil && self.isTunnelEstablished)
                                
                                // Map internal state to NEVPNStatus equivalents
                                let statusRawValue: Int
                                let statusDescription: String
                                
                                if isSessionReady {
                                    statusRawValue = NEVPNStatus.connected.rawValue
                                    statusDescription = "Connected"
                                } else if isPacketProcessing || handshakeCompletion != nil {
                                    statusRawValue = NEVPNStatus.connecting.rawValue
                                    statusDescription = "Connecting"
                                } else {
                                    statusRawValue = NEVPNStatus.disconnected.rawValue
                                    statusDescription = "Disconnected"
                                }

                                // Add extra debug information
                                var debugInfo: [String: String] = [
                                    "TunnelEstablished": "\(self.isTunnelEstablished)",
                                    "PacketProcessing": "\(self.isPacketProcessing)",
                                    "Handshaking": "\(self.handshakeCompletion != nil)",
                                    "SessionKeyExists": "\(self.sessionKey != nil)",
                                    "ServerPublicKeyExists": "\(self.serverPublicKey != nil)",
                                    "ReconnectAttempts": "\(self.reconnectAttempts)/\(self.maxReconnectAttempts)"
                                ]
                                
                                if let wsTask = self.webSocketTask {
                                    debugInfo["WebSocketState"] = "\(wsTask.state.rawValue)" // 0=suspended, 1=running, 2=completed, 3=cancelled
                                    debugInfo["WebSocketCloseCode"] = "\(wsTask.closeCode.rawValue)"
                                    if let closeReason = wsTask.closeReason {
                                        debugInfo["WebSocketCloseReason"] = String(data: closeReason, encoding: .utf8) ?? "Cannot decode"
                                    }
                                } else {
                                    debugInfo["WebSocket"] = "None"
                                }
                                
                                // Add last error if any
                                if let lastError = self.lastError {
                                    debugInfo["LastError"] = getDetailedError(lastError)
                                }
                                
                                // Add config info
                                if let providerConfig = self.protocolConfiguration as? NETunnelProviderProtocol,
                                   let configDict = providerConfig.providerConfiguration {
                                    
                                    if let serverAddress = configDict["ServerAddress"] as? String {
                                        debugInfo["ServerAddress"] = serverAddress
                                    }
                                    
                                    if let serverPort = configDict["ServerPort"] {
                                        debugInfo["ServerPort"] = "\(serverPort)"
                                    }
                                }

                                let status = StatusResponse(
                                    isConnected: isSessionReady,
                                    vpnStatusRawValue: statusRawValue,
                                    vpnStatusDescription: statusDescription,
                                    sessionId: self.sessionId ?? "Not Assigned",
                                    assignedIp: self.assignedTunnelIP ?? "Not Assigned",
                                    debugInfo: debugInfo
                                )
                                
                                os_log("Sending status response with %d debug info items", log: log, type: .debug, debugInfo.count)
                                let responseData = try JSONEncoder().encode(status)
                                responseHandler(responseData)

                            case "disconnect":
                                // Request to disconnect comes from app
                                os_log("Disconnect request received from app.", log: log, type: .info)
                                // Use stopTunnel which calls cleanupResources
                                stopTunnel(with: .userInitiated) {}
                                // Acknowledge command received immediately - use all strings to avoid type conflicts
                                let response: [String: String] = ["ack": "true", "status": "disconnecting"]
                                responseHandler(try? JSONEncoder().encode(response))

                            // Add other message types as needed
                            case "debug":
                                // Return debug information about internal state in a dictionary that can be serialized
                                var debugInfo: [String: String] = [
                                    "tunnelEstablished": "\(self.isTunnelEstablished)",
                                    "packetProcessing": "\(self.isPacketProcessing)",
                                    "reconnectAttempts": "\(self.reconnectAttempts)",
                                    "maxReconnectAttempts": "\(self.maxReconnectAttempts)",
                                    "hasSessionKey": "\(self.sessionKey != nil)",
                                    "hasServerPublicKey": "\(self.serverPublicKey != nil)",
                                    "hasWebSocketTask": "\(self.webSocketTask != nil)",
                                    "sessionId": self.sessionId ?? "Not Assigned",
                                    "assignedTunnelIP": self.assignedTunnelIP ?? "Not Assigned"
                                ]
                                
                                // Add configuration information
                                if let providerConfig = self.protocolConfiguration as? NETunnelProviderProtocol,
                                   let configDict = providerConfig.providerConfiguration {
                                    // Add config info without having to directly serialize the dictionary
                                    for (key, value) in configDict {
                                        debugInfo["config_\(key)"] = "\(value)"
                                    }
                                }
                                
                                // Add last error if any
                                if let lastError = self.lastError {
                                    debugInfo["lastErrorDescription"] = lastError.localizedDescription
                                    if let nsError = lastError as? NSError {
                                        debugInfo["lastErrorCode"] = "\(nsError.code)"
                                        debugInfo["lastErrorDomain"] = nsError.domain
                                    }
                                }
                                
                                os_log("Sending debug info response", log: log, type: .debug)
                                let responseData = try JSONEncoder().encode(debugInfo)
                                responseHandler(responseData)

                            default:
                                os_log("Unknown app message type: %{public}s", log: log, type: .default, type)
                                let response: [String: String] = [
                                    "error": "Unknown message type",
                                    "receivedType": type
                                ]
                                responseHandler(try? JSONEncoder().encode(response))
                            }
                        } catch {
                            os_log("Error processing app message: %{public}@", log: log, type: .error, error.localizedDescription)
                            let response: [String: String] = [
                                "error": "Failed to process message",
                                "details": error.localizedDescription
                            ]
                            responseHandler(try? JSONEncoder().encode(response))
                        }
                    }
                 }

                 // Helper: Make NEVPNStatus description more readable in logs
                 extension NEVPNStatus: CustomStringConvertible {
                      public var description: String {
                          switch self {
                          case .disconnected: return "Disconnected"
                          case .invalid: return "Invalid"
                          case .connecting: return "Connecting"
                          case .connected: return "Connected"
                          case .reasserting: return "Reasserting"
                          case .disconnecting: return "Disconnecting"
                          @unknown default: return "Unknown"
                          }
                      }
                 }

                 // Note: KeychainManager and Data extensions (Base58, HexString) need to be implemented separately.
                 // Note: Ensure AeronyxCrypto FFI wrapper and Rust library are correctly linked/imported.
