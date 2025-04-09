import Foundation
import NetworkExtension
import Combine
import os.log

class VPNManager: ObservableObject {
    private let cryptoManager = CryptoManager()
    private let vpnBundleIdentifier = "com.aeronyx.AeroNyx.ed25519"
    private let serverAddress = "your-vpn-server.com"
    private let log = OSLog(subsystem: "com.aeronyx.AeroNyx", category: "VPNManager")
    
    @Published var isConnected = false
    @Published var connectionInProgress = false
    @Published var statusMessage = "Not Connected"
    @Published var solanaAddress = "Not Generated"
    
    private var statusObserver: Any?
    
    init() {
        // Monitor VPN status changes
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let connection = notification.object as? NEVPNConnection else {
                return
            }
            self.updateStatus(with: connection.status)
        }
        
        // Initialize by loading status
        loadStatus()
    }
    
    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }
    
    func loadStatus() {
        // Load Solana account status
        loadSolanaAccount()
        
        // Load VPN connection status
        loadVPNStatus()
    }
    
    private func loadSolanaAccount() {
        if cryptoManager.isKeypairAvailable() {
            do {
                let keypair = try cryptoManager.loadKeypair()
                DispatchQueue.main.async {
                    self.solanaAddress = keypair.publicKeyString
                }
            } catch {
                os_log("Failed to load keypair: %{public}@", log: log, type: .error, error.localizedDescription)
                DispatchQueue.main.async {
                    self.solanaAddress = "Loading Failed"
                }
            }
        } else {
            DispatchQueue.main.async {
                self.solanaAddress = "Not Generated"
            }
        }
    }
    
    private func loadVPNStatus() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                os_log("Failed to load VPN configurations: %{public}@", log: self.log, type: .error, error.localizedDescription)
                return
            }
            
            // Find manager for our VPN
            let vpnManager = managers?.first { manager in
                if let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
                    return tunnelProtocol.providerBundleIdentifier == self.vpnBundleIdentifier
                }
                return false
            }
            
            DispatchQueue.main.async {
                if let manager = vpnManager {
                    self.updateStatus(with: manager.connection.status)
                } else {
                    self.statusMessage = "Not Configured"
                    self.isConnected = false
                    self.connectionInProgress = false
                }
            }
        }
    }
    
    private func updateStatus(with status: NEVPNStatus) {
        DispatchQueue.main.async {
            switch status {
            case .connected:
                self.isConnected = true
                self.connectionInProgress = false
                self.statusMessage = "Connected"
            case .connecting:
                self.isConnected = false
                self.connectionInProgress = true
                self.statusMessage = "Connecting..."
            case .disconnecting:
                self.isConnected = false
                self.connectionInProgress = true
                self.statusMessage = "Disconnecting..."
            case .reasserting:
                self.isConnected = false
                self.connectionInProgress = true
                self.statusMessage = "Reconnecting..."
            case .invalid, .disconnected:
                self.isConnected = false
                self.connectionInProgress = false
                self.statusMessage = "Not Connected"
            @unknown default:
                self.isConnected = false
                self.connectionInProgress = false
                self.statusMessage = "Unknown Status"
            }
        }
    }
    
    func toggleVPN(completion: @escaping (Error?) -> Void) {
        if isConnected {
            disconnectVPN(completion: completion)
        } else {
            connectVPN(completion: completion)
        }
    }
    
    private func connectVPN(completion: @escaping (Error?) -> Void) {
        // Check if Solana account is available
        guard cryptoManager.isKeypairAvailable() else {
            let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1001, userInfo: [
                NSLocalizedDescriptionKey: "Solana account not available. Please generate or import one."
            ])
            completion(error)
            return
        }
        
        DispatchQueue.main.async {
            self.connectionInProgress = true
            self.statusMessage = "Connecting..."
        }
        
        // Load existing configuration or create new one
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                self.handleConnectionError(error, message: "Failed to load configuration", completion: completion)
                return
            }
            
            // Find existing configuration or create new one
            let manager: NETunnelProviderManager
            
            // Look for existing configuration
            if let existingManager = managers?.first(where: { manager in
                if let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
                    return tunnelProtocol.providerBundleIdentifier == self.vpnBundleIdentifier
                }
                return false
            }) {
                manager = existingManager
            } else {
                // Create new configuration
                manager = NETunnelProviderManager()
                
                // Create tunnel configuration
                let tunnelProtocol = NETunnelProviderProtocol()
                tunnelProtocol.providerBundleIdentifier = self.vpnBundleIdentifier
                tunnelProtocol.serverAddress = self.serverAddress
                
                // Configure additional settings
                var providerConfig = [String: Any]()
                providerConfig["ServerAddress"] = self.serverAddress
                tunnelProtocol.providerConfiguration = providerConfig
                
                manager.protocolConfiguration = tunnelProtocol
                manager.localizedDescription = "AeroNyx VPN"
            }
            
            // Ensure VPN is enabled
            manager.isEnabled = true
            
            // Save configuration
            manager.saveToPreferences { error in
                if let error = error {
                    self.handleConnectionError(error, message: "Failed to save configuration", completion: completion)
                    return
                }
                
                // Start VPN
                do {
                    try manager.connection.startVPNTunnel()
                    completion(nil)
                } catch {
                    self.handleConnectionError(error, message: "Failed to start tunnel", completion: completion)
                }
            }
        }
    }
    
    private func disconnectVPN(completion: @escaping (Error?) -> Void) {
        DispatchQueue.main.async {
            self.connectionInProgress = true
            self.statusMessage = "Disconnecting..."
        }
        
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                self.handleConnectionError(error, message: "Failed to load configuration", completion: completion)
                return
            }
            
            // Find our manager
            let vpnManager = managers?.first { manager in
                if let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
                    return tunnelProtocol.providerBundleIdentifier == self.vpnBundleIdentifier
                }
                return false
            }
            
            if let manager = vpnManager {
                manager.connection.stopVPNTunnel()
                completion(nil)
            } else {
                let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1014, userInfo: [
                    NSLocalizedDescriptionKey: "VPN configuration not found"
                ])
                self.handleConnectionError(error, message: "VPN configuration not found", completion: completion)
            }
        }
    }
    
    private func handleConnectionError(_ error: Error, message: String, completion: @escaping (Error?) -> Void) {
        os_log("VPN error: %{public}@, %{public}@", log: log, type: .error, message, error.localizedDescription)
        
        DispatchQueue.main.async {
            self.connectionInProgress = false
            self.statusMessage = message
            completion(error)
        }
    }
    
    // MARK: - Account Management
    
    func generateNewAccount(completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            let keypair = try cryptoManager.generateNewKeypair()
            DispatchQueue.main.async {
                self.solanaAddress = keypair.publicKeyString
                completion(.success(()))
            }
        } catch {
            os_log("Failed to generate keypair: %{public}@", log: log, type: .error, error.localizedDescription)
            DispatchQueue.main.async {
                completion(.failure(error))
            }
        }
    }
    
    func importPrivateKey(_ privateKeyString: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard !privateKeyString.isEmpty else {
            let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1015, userInfo: [
                NSLocalizedDescriptionKey: "Private key cannot be empty"
            ])
            DispatchQueue.main.async {
                completion(.failure(error))
            }
            return
        }
        
        do {
            try cryptoManager.importKeypair(from: privateKeyString)
            // Reload account information
            loadSolanaAccount()
            DispatchQueue.main.async {
                completion(.success(()))
            }
        } catch {
            os_log("Failed to import keypair: %{public}@", log: log, type: .error, error.localizedDescription)
            DispatchQueue.main.async {
                completion(.failure(error))
            }
        }
    }
    
    // MARK: - Extension Communication
    
    func sendMessageToExtension(_ message: [String: Any], completion: @escaping (Result<[String: Any]?, Error>) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(.failure(error))
                return
            }
            
            // Find our manager
            guard let manager = managers?.first(where: { manager in
                if let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol {
                    return tunnelProtocol.providerBundleIdentifier == self.vpnBundleIdentifier
                }
                return false
            }),
            let session = manager.connection as? NETunnelProviderSession else {
                let error = NSError(domain: "com.aeronyx.AeroNyx", code: 1016, userInfo: [
                    NSLocalizedDescriptionKey: "VPN tunnel not found"
                ])
                completion(.failure(error))
                return
            }
            
            do {
                let messageData = try JSONSerialization.data(withJSONObject: message, options: [])
                try session.sendProviderMessage(messageData) { responseData in
                    if let responseData = responseData {
                        do {
                            let response = try JSONSerialization.jsonObject(with: responseData, options: []) as? [String: Any]
                            completion(.success(response))
                        } catch {
                            completion(.failure(error))
                        }
                    } else {
                        completion(.success(nil))
                    }
                }
            } catch {
                completion(.failure(error))
            }
        }
    }
}
