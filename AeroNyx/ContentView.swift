//
//  ContentView.swift
//  AeroNyx
//
//  Created by yuanyuan on 2025/4/6.
//

import SwiftUI
import NetworkExtension

struct ContentView: View {
    @StateObject private var vpnManager = VPNManager()
    @State private var showingAccountSheet = false
    @State private var showingErrorAlert = false
    @State private var errorMessage = ""
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: vpnManager.isConnected ? "lock.shield.fill" : "lock.shield")
                .imageScale(.large)
                .foregroundStyle(vpnManager.isConnected ? .green : .gray)
                .font(.system(size: 60))
            
            Text("AeroNyx VPN")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            Text(vpnManager.statusMessage)
                .font(.headline)
                .foregroundColor(statusColor)
            
            Divider()
            
            // Solana账号信息
            VStack(alignment: .leading) {
                Text("Solana账号")
                    .font(.headline)
                
                HStack {
                    Text(vpnManager.solanaAddress)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    Button(action: {
                        copyToClipboard(vpnManager.solanaAddress)
                    }) {
                        Image(systemName: "doc.on.doc")
                    }
                    .disabled(vpnManager.solanaAddress == "未生成")
                }
                
                Button("管理账号") {
                    showingAccountSheet = true
                }
                .padding(.top, 8)
            }
            .padding()
            .background(Color.gray.opacity(0.1))
            .cornerRadius(8)
            .padding(.horizontal)
            
            Spacer()
            
            Button(action: {
                vpnManager.toggleVPN { error in
                    if let error = error {
                        errorMessage = "VPN操作失败: \(error.localizedDescription)"
                        showingErrorAlert = true
                    }
                }
            }) {
                if vpnManager.connectionInProgress {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .frame(width: 20, height: 20)
                } else {
                    Text(vpnManager.isConnected ? "断开连接" : "连接")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            .disabled(vpnManager.connectionInProgress || vpnManager.solanaAddress == "未生成")
            .padding()
            .frame(minWidth: 200)
            .background(buttonColor)
            .cornerRadius(10)
        }
        .padding()
        .frame(minWidth: 300, minHeight: 400)
        .onAppear {
            vpnManager.loadStatus()
        }
        .sheet(isPresented: $showingAccountSheet) {
            AccountView(vpnManager: vpnManager)
        }
        .alert("错误", isPresented: $showingErrorAlert) {
            Button("确定", role: .cancel) {}
        } message: {
            Text(errorMessage)
        }
    }
    
    private var statusColor: Color {
        if vpnManager.isConnected {
            return .green
        } else if vpnManager.connectionInProgress {
            return .orange
        } else {
            return .gray
        }
    }
    
    private var buttonColor: Color {
        if vpnManager.isConnected {
            return Color.red
        } else if vpnManager.connectionInProgress || vpnManager.solanaAddress == "未生成" {
            return Color.gray
        } else {
            return Color.blue
        }
    }
    
    private func copyToClipboard(_ string: String) {
        #if os(macOS)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(string, forType: .string)
        #else
        UIPasteboard.general.string = string
        #endif
    }
}

// MARK: - 账号管理视图

struct AccountView: View {
    @ObservedObject var vpnManager: VPNManager
    @Environment(\.presentationMode) var presentationMode
    @State private var privateKeyInput = ""
    @State private var showingImportAlert = false
    @State private var showingAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("当前Solana账号")) {
                    Text(vpnManager.solanaAddress)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    
                    Button("复制地址") {
                        #if os(macOS)
                        let pasteboard = NSPasteboard.general
                        pasteboard.clearContents()
                        pasteboard.setString(vpnManager.solanaAddress, forType: .string)
                        #else
                        UIPasteboard.general.string = vpnManager.solanaAddress
                        #endif
                    }
                    .disabled(vpnManager.solanaAddress == "未生成" || vpnManager.solanaAddress == "加载失败")
                }
                
                Section(header: Text("账号管理")) {
                    Button("生成新账号") {
                        vpnManager.generateNewAccount { result in
                            switch result {
                            case .success:
                                alertTitle = "成功"
                                alertMessage = "已生成新的Solana账号"
                            case .failure(let error):
                                alertTitle = "错误"
                                alertMessage = "生成账号失败: \(error.localizedDescription)"
                            }
                            showingAlert = true
                        }
                    }
                    
                    Button("导入私钥") {
                        showingImportAlert = true
                    }
                }
            }
            .navigationTitle("Solana账号管理")
            .navigationBarItems(trailing: Button("完成") {
                presentationMode.wrappedValue.dismiss()
            })
            .alert(isPresented: $showingAlert) {
                Alert(
                    title: Text(alertTitle),
                    message: Text(alertMessage),
                    dismissButton: .default(Text("确定"))
                )
            }
            .alert("导入私钥", isPresented: $showingImportAlert) {
                TextField("输入私钥 (十六进制或Base58)", text: $privateKeyInput)
                Button("取消", role: .cancel) {}
                Button("导入") {
                    vpnManager.importPrivateKey(privateKeyInput) { result in
                        privateKeyInput = ""
                        switch result {
                        case .success:
                            alertTitle = "成功"
                            alertMessage = "已导入Solana账号"
                        case .failure(let error):
                            alertTitle = "错误"
                            alertMessage = "导入私钥失败: \(error.localizedDescription)"
                        }
                        showingAlert = true
                    }
                }
            } message: {
                Text("注意：请确保私钥来源安全可靠，导入后将覆盖现有账号。")
            }
        }
    }
}

// MARK: - VPN管理器

class VPNManager: ObservableObject {
    private let cryptoManager = CryptoManager()
    private let vpnBundleIdentifier = "Amaterasu.AeroNyx.ed25519"
    
    @Published var isConnected = false
    @Published var connectionInProgress = false
    @Published var statusMessage = "未连接"
    @Published var solanaAddress = "未生成"
    
    init() {
        // 监听VPN状态变化
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusDidChange),
            name: .NEVPNStatusDidChange,
            object: nil
        )
        
        // 初始化时加载状态
        loadStatus()
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    func loadStatus() {
        // 加载Solana账号状态
        loadSolanaAccount()
        
        // 加载VPN连接状态
        loadVPNStatus()
    }
    
    private func loadSolanaAccount() {
        if cryptoManager.isKeypairAvailable() {
            do {
                let keypair = try cryptoManager.loadKeypair()
                solanaAddress = keypair.publicKeyString
            } catch {
                solanaAddress = "加载失败"
            }
        } else {
            solanaAddress = "未生成"
        }
    }
    
    private func loadVPNStatus() {
        let manager = NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                print("加载VPN配置失败: \(error.localizedDescription)")
                return
            }
            
            // 获取对应我们VPN的管理器
            let vpnManager = managers?.first(where: { $0.providerBundleIdentifier == self.vpnBundleIdentifier })
            
            DispatchQueue.main.async {
                if let manager = vpnManager {
                    self.updateStatus(with: manager.connection.status)
                } else {
                    self.statusMessage = "未配置"
                }
            }
        }
    }
    
    @objc private func vpnStatusDidChange(_ notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else { return }
        
        DispatchQueue.main.async {
            self.updateStatus(with: connection.status)
        }
    }
    
    private func updateStatus(with status: NEVPNStatus) {
        switch status {
        case .connected:
            isConnected = true
            connectionInProgress = false
            statusMessage = "已连接"
        case .connecting:
            isConnected = false
            connectionInProgress = true
            statusMessage = "连接中..."
        case .disconnecting:
            isConnected = false
            connectionInProgress = true
            statusMessage = "断开连接中..."
        case .reasserting:
            isConnected = false
            connectionInProgress = true
            statusMessage = "重新连接中..."
        case .invalid, .disconnected:
            isConnected = false
            connectionInProgress = false
            statusMessage = "未连接"
        @unknown default:
            isConnected = false
            connectionInProgress = false
            statusMessage = "未知状态"
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
        connectionInProgress = true
        statusMessage = "正在连接..."
        
        // 先加载已有配置或创建新配置
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                DispatchQueue.main.async {
                    self.connectionInProgress = false
                    self.statusMessage = "加载配置失败"
                    completion(error)
                }
                return
            }
            
            // 查找已有的配置或创建新的
            let manager: NETunnelProviderManager
            if let existingManager = managers?.first(where: { $0.providerBundleIdentifier == self.vpnBundleIdentifier }) {
                manager = existingManager
            } else {
                manager = NETunnelProviderManager()
                
                // 创建隧道配置
                let tunnelProtocol = NETunnelProviderProtocol()
                tunnelProtocol.providerBundleIdentifier = self.vpnBundleIdentifier
                tunnelProtocol.serverAddress = "AeroNyx VPN" // 显示名称
                
                manager.protocolConfiguration = tunnelProtocol
                manager.localizedDescription = "AeroNyx VPN"
            }
            
            // 确保VPN已启用
            manager.isEnabled = true
            
            // 保存配置
            manager.saveToPreferences { error in
                if let error = error {
                    DispatchQueue.main.async {
                        self.connectionInProgress = false
                        self.statusMessage = "保存配置失败"
                        completion(error)
                    }
                    return
                }
                
                // 启动VPN
                do {
                    try manager.connection.startVPNTunnel()
                    completion(nil)
                } catch {
                    DispatchQueue.main.async {
                        self.connectionInProgress = false
                        self.statusMessage = "启动隧道失败"
                        completion(error)
                    }
                }
            }
        }
    }
    
    private func disconnectVPN(completion: @escaping (Error?) -> Void) {
        connectionInProgress = true
        statusMessage = "正在断开连接..."
        
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            
            if let error = error {
                DispatchQueue.main.async {
                    self.connectionInProgress = false
                    completion(error)
                }
                return
            }
            
            if let manager = managers?.first(where: { $0.providerBundleIdentifier == self.vpnBundleIdentifier }) {
                manager.connection.stopVPNTunnel()
                completion(nil)
            } else {
                DispatchQueue.main.async {
                    self.connectionInProgress = false
                    self.statusMessage = "未找到VPN配置"
                    completion(NSError(domain: "com.aeronyx.AeroNyx", code: 1014, userInfo: [NSLocalizedDescriptionKey: "未找到VPN配置"]))
                }
            }
        }
    }
    
    func generateNewAccount(completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            let keypair = try cryptoManager.generateNewKeypair()
            DispatchQueue.main.async {
                self.solanaAddress = keypair.publicKeyString
                completion(.success(()))
            }
        } catch {
            DispatchQueue.main.async {
                completion(.failure(error))
            }
        }
    }
    
    func importPrivateKey(_ privateKeyString: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard !privateKeyString.isEmpty else {
            DispatchQueue.main.async {
                completion(.failure(NSError(domain: "com.aeronyx.AeroNyx", code: 1015, userInfo: [NSLocalizedDescriptionKey: "私钥不能为空"])))
            }
            return
        }
        
        do {
            try cryptoManager.importKeypair(from: privateKeyString)
            // 重新加载账户信息
            loadSolanaAccount()
            DispatchQueue.main.async {
                completion(.success(()))
            }
        } catch {
            DispatchQueue.main.async {
                completion(.failure(error))
            }
        }
    }
}
