//
//  ContentView.swift
//  AeroNyx
//
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
            
            // Solana account information
            VStack(alignment: .leading) {
                Text("Solana Account")
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
                    .disabled(vpnManager.solanaAddress == "Not Generated")
                }
                
                Button("Manage Account") {
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
                        errorMessage = "VPN operation failed: \(error.localizedDescription)"
                        showingErrorAlert = true
                    }
                }
            }) {
                if vpnManager.connectionInProgress {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle())
                        .frame(width: 20, height: 20)
                } else {
                    Text(vpnManager.isConnected ? "Disconnect" : "Connect")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            .disabled(vpnManager.connectionInProgress || vpnManager.solanaAddress == "Not Generated")
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
        .alert("Error", isPresented: $showingErrorAlert) {
            Button("OK", role: .cancel) {}
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
        } else if vpnManager.connectionInProgress || vpnManager.solanaAddress == "Not Generated" {
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

// MARK: - Account Management View

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
                Section(header: Text("Current Solana Account")) {
                    Text(vpnManager.solanaAddress)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    
                    Button("Copy Address") {
                        #if os(macOS)
                        let pasteboard = NSPasteboard.general
                        pasteboard.clearContents()
                        pasteboard.setString(vpnManager.solanaAddress, forType: .string)
                        #else
                        UIPasteboard.general.string = vpnManager.solanaAddress
                        #endif
                    }
                    .disabled(vpnManager.solanaAddress == "Not Generated" || vpnManager.solanaAddress == "Loading Failed")
                }
                
                Section(header: Text("Account Management")) {
                    Button("Generate New Account") {
                        vpnManager.generateNewAccount { result in
                            switch result {
                            case .success:
                                alertTitle = "Success"
                                alertMessage = "New Solana account generated"
                            case .failure(let error):
                                alertTitle = "Error"
                                alertMessage = "Failed to generate account: \(error.localizedDescription)"
                            }
                            showingAlert = true
                        }
                    }
                    
                    Button("Import Private Key") {
                        showingImportAlert = true
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button("Done") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
            .alert(isPresented: $showingAlert) {
                Alert(
                    title: Text(alertTitle),
                    message: Text(alertMessage),
                    dismissButton: .default(Text("OK"))
                )
            }
            .alert("Import Private Key", isPresented: $showingImportAlert) {
                TextField("Enter private key (hex or Base58)", text: $privateKeyInput)
                Button("Cancel", role: .cancel) {}
                Button("Import") {
                    vpnManager.importPrivateKey(privateKeyInput) { result in
                        privateKeyInput = ""
                        switch result {
                        case .success:
                            alertTitle = "Success"
                            alertMessage = "Solana account imported"
                        case .failure(let error):
                            alertTitle = "Error"
                            alertMessage = "Failed to import private key: \(error.localizedDescription)"
                        }
                        showingAlert = true
                    }
                }
            } message: {
                Text("Note: Please ensure the private key is from a trusted source. Importing will replace any existing account.")
            }
        }
    }
}
