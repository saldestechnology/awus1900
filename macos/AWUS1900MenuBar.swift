import AppKit
import Foundation
import UniformTypeIdentifiers

private struct AccessPoint: Decodable {
    let bssid: String
    let channel: Int
    let rssi: Int
    let security: String
    let wpa2_psk: Bool
    let sae: Bool
    let sae_h2e: Bool
    let ssid_hex: String

    var displaySSID: String {
        guard let bytes = Self.bytes(fromHex: ssid_hex), !bytes.isEmpty else {
            return "<hidden>"
        }
        return String(decoding: bytes, as: UTF8.self)
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\t", with: "\\t")
    }

    static func bytes(fromHex hex: String) -> [UInt8]? {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result
    }
}

@main
private struct AWUS1900MenuBarApp {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var controller: ControllerWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        controller = ControllerWindow()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "AWUS1900"

        let menu = NSMenu()
        menu.addItem(withTitle: "Open Controller", action: #selector(openController), keyEquivalent: "")
        menu.addItem(withTitle: "Scan Networks", action: #selector(scanNetworks), keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit AWUS1900", action: #selector(quitApp), keyEquivalent: "q")
        for item in menu.items { item.target = self }
        statusItem.menu = menu
        controller.showWindow()
    }

    @objc private func openController() {
        controller.showWindow()
    }

    @objc private func scanNetworks() {
        controller.scanNetworks()
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }
}

private final class ControllerWindow: NSObject, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private let window: NSWindow
    private let firmwareField = NSTextField()
    private let channelField = NSTextField()
    private let dwellField = NSTextField(string: "250")
    private let regionPopup = NSPopUpButton()
    private let securityPopup = NSPopUpButton()
    private let passphraseField = NSSecureTextField()
    private let scanButton = NSButton(title: "Passive Scan", target: nil, action: nil)
    private let joinButton = NSButton(title: "Join and Verify Handshake", target: nil, action: nil)
    private let stopButton = NSButton(title: "Stop", target: nil, action: nil)
    private let tableView = NSTableView()
    private let outputView = NSTextView()
    private let statusLabel = NSTextField(labelWithString: "Select firmware, then scan. Scanning only listens.")

    private var accessPoints: [AccessPoint] = []
    private var selectedAccessPoint: AccessPoint? {
        let row = tableView.selectedRow
        return accessPoints.indices.contains(row) ? accessPoints[row] : nil
    }
    private var activeProcess: Process?
    private var outputPipe: Pipe?
    private var diagnosticsPipe: Pipe?
    private let outputLock = NSLock()
    private var capturedOutput = Data()

    override init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 820, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        self.window = window
        super.init()
        window.title = "AWUS1900 Controller"
        window.minSize = NSSize(width: 760, height: 680)
        window.delegate = self
        buildInterface()
        loadSavedFirmwarePath()
        window.center()
    }

    func showWindow() {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func scanNetworks() {
        guard activeProcess == nil else { return }
        guard let firmware = validatedFirmwarePath() else { return }
        let channels = channelField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard channels.isEmpty || Self.validChannels(channels) else {
            setStatus("Enter supported comma-separated channels, or leave blank to scan all supported channels.")
            return
        }
        guard let dwell = Int(dwellField.stringValue), (50...5000).contains(dwell) else {
            setStatus("Dwell time must be between 50 and 5000 milliseconds.")
            return
        }

        accessPoints = []
        tableView.reloadData()
        securityPopup.removeAllItems()
        securityPopup.addItem(withTitle: "Choose a network first")
        appendOutput("Starting passive scan…\n")
        setBusy(true, status: "Scanning selected channels. This operation sends no RF frames.")
        var arguments = ["--dwell-ms", String(dwell), "--fw", firmware, "--json"]
        if !channels.isEmpty {
            arguments.append(contentsOf: ["--channels", channels])
        }
        runTool("rtlscan", arguments: arguments, showOutput: false) { [weak self] status, output in
            guard let self else { return }
            self.setBusy(false, status: status == 0 ? "Passive scan complete." : "Scan failed. See output below.")
            guard status == 0 else {
                self.appendOutput(output)
                return
            }
            do {
                self.accessPoints = try JSONDecoder().decode([AccessPoint].self, from: Data(output.utf8))
                self.tableView.reloadData()
                self.appendOutput("\nFound \(self.accessPoints.count) network(s). Select one to continue.\n")
            } catch {
                self.appendOutput("Could not parse scan results: \(error.localizedDescription)\n")
                self.setStatus("Scan completed, but its result could not be parsed.")
            }
        }
    }

    private func buildInterface() {
        let content = NSStackView()
        content.orientation = .vertical
        content.alignment = .leading
        content.distribution = .fill
        content.spacing = 10
        content.translatesAutoresizingMaskIntoConstraints = false

        let firmwareRow = NSStackView()
        firmwareRow.orientation = .horizontal
        firmwareRow.alignment = .centerY
        firmwareRow.spacing = 8
        firmwareField.placeholderString = "Choose the licensed RTL8814A firmware file"
        firmwareField.stringValue = UserDefaults.standard.string(forKey: "firmwarePath") ?? ""
        firmwareField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let browseButton = NSButton(title: "Choose Firmware…", target: self, action: #selector(browseFirmware))
        firmwareRow.addArrangedSubview(firmwareField)
        firmwareRow.addArrangedSubview(browseButton)

        let scanOptions = NSStackView()
        scanOptions.orientation = .horizontal
        scanOptions.alignment = .centerY
        scanOptions.spacing = 8
        channelField.placeholderString = "All supported"
        channelField.widthAnchor.constraint(equalToConstant: 160).isActive = true
        dwellField.widthAnchor.constraint(equalToConstant: 72).isActive = true
        let scanAction = configureButton(scanButton, action: #selector(scanAction))
        let stopAction = configureButton(stopButton, action: #selector(stopAction))
        stopButton.isEnabled = false
        scanOptions.addArrangedSubview(NSView.label("Channels (optional):"))
        scanOptions.addArrangedSubview(channelField)
        scanOptions.addArrangedSubview(NSView.label("Dwell (ms):"))
        scanOptions.addArrangedSubview(dwellField)
        scanOptions.addArrangedSubview(scanAction)
        scanOptions.addArrangedSubview(stopAction)

        for (identifier, title, width) in [
            ("ssid", "SSID", 210.0),
            ("bssid", "BSSID", 150.0),
            ("channel", "Ch", 50.0),
            ("rssi", "RSSI", 55.0),
            ("security", "Security", 165.0)
        ] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.headerView = NSTableHeaderView()
        tableView.delegate = self
        tableView.dataSource = self
        tableView.frame = NSRect(x: 0, y: 0, width: 630, height: 200)
        tableView.autoresizingMask = [.width]
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.selectionHighlightStyle = .regular
        let tableScroll = NSScrollView()
        tableScroll.documentView = tableView
        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder
        tableScroll.translatesAutoresizingMaskIntoConstraints = false
        tableScroll.heightAnchor.constraint(equalToConstant: 200).isActive = true

        regionPopup.addItem(withTitle: "Choose regulatory region…")
        for region in ["fcc", "mkk", "etsi", "ic", "kcc", "acma", "chile", "ukraine", "mexico", "cn", "qatar", "uk", "ww"] {
            regionPopup.addItem(withTitle: region.uppercased())
        }
        securityPopup.addItem(withTitle: "Choose a network first")
        regionPopup.target = self
        regionPopup.action = #selector(selectionChanged)
        securityPopup.target = self
        securityPopup.action = #selector(selectionChanged)
        passphraseField.placeholderString = "WPA2 / WPA3 passphrase"
        regionPopup.widthAnchor.constraint(equalToConstant: 125).isActive = true
        securityPopup.widthAnchor.constraint(equalToConstant: 140).isActive = true
        passphraseField.widthAnchor.constraint(equalToConstant: 150).isActive = true
        joinButton.widthAnchor.constraint(equalToConstant: 195).isActive = true
        passphraseField.isEnabled = false
        regionPopup.isEnabled = false
        securityPopup.isEnabled = false

        let joinRow = NSStackView()
        joinRow.orientation = .horizontal
        joinRow.alignment = .centerY
        joinRow.spacing = 8
        joinRow.addArrangedSubview(NSView.label("Region:"))
        joinRow.addArrangedSubview(regionPopup)
        joinRow.addArrangedSubview(NSView.label("Security:"))
        joinRow.addArrangedSubview(securityPopup)
        joinRow.addArrangedSubview(passphraseField)
        joinRow.addArrangedSubview(configureButton(joinButton, action: #selector(joinAction)))
        joinButton.isEnabled = false

        statusLabel.lineBreakMode = .byWordWrapping
        statusLabel.maximumNumberOfLines = 2
        let outputScroll = NSScrollView()
        outputScroll.documentView = outputView
        outputScroll.hasVerticalScroller = true
        outputScroll.borderType = .bezelBorder
        outputScroll.translatesAutoresizingMaskIntoConstraints = false
        outputScroll.heightAnchor.constraint(equalToConstant: 175).isActive = true
        outputView.frame = NSRect(x: 0, y: 0, width: 760, height: 175)
        outputView.isEditable = false
        outputView.isVerticallyResizable = true
        outputView.isHorizontallyResizable = false
        outputView.autoresizingMask = [.width]
        outputView.minSize = NSSize(width: 0, height: 175)
        outputView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        outputView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        outputView.textContainerInset = NSSize(width: 6, height: 6)
        outputView.textContainer?.containerSize = NSSize(width: 760, height: CGFloat.greatestFiniteMagnitude)
        outputView.textContainer?.widthTracksTextView = true

        content.addArrangedSubview(NSView.label("Firmware is not bundled. Select a local firmware file whose redistribution terms permit your use."))
        content.addArrangedSubview(firmwareRow)
        content.addArrangedSubview(scanOptions)
        content.addArrangedSubview(tableScroll)
        content.addArrangedSubview(joinRow)
        content.addArrangedSubview(statusLabel)
        content.addArrangedSubview(outputScroll)

        window.contentView = NSView()
        guard let root = window.contentView else { return }
        root.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            content.bottomAnchor.constraint(lessThanOrEqualTo: root.bottomAnchor, constant: -16),
            tableScroll.widthAnchor.constraint(equalTo: content.widthAnchor),
            outputScroll.widthAnchor.constraint(equalTo: content.widthAnchor),
            firmwareRow.widthAnchor.constraint(equalTo: content.widthAnchor),
            scanOptions.widthAnchor.constraint(equalTo: content.widthAnchor),
            joinRow.widthAnchor.constraint(equalTo: content.widthAnchor),
            statusLabel.widthAnchor.constraint(equalTo: content.widthAnchor)
        ])
    }

    private func configureButton(_ button: NSButton, action: Selector) -> NSButton {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
        return button
    }

    private static func validChannels(_ value: String) -> Bool {
        let pieces = value.split(separator: ",", omittingEmptySubsequences: false)
        guard !pieces.isEmpty else { return false }
        return pieces.allSatisfy { piece in
            guard let channel = Int(piece.trimmingCharacters(in: .whitespaces)), (1...177).contains(channel) else { return false }
            return true
        }
    }

    private func loadSavedFirmwarePath() {
        firmwareField.stringValue = UserDefaults.standard.string(forKey: "firmwarePath") ?? ""
    }

    private func validatedFirmwarePath() -> String? {
        let path = firmwareField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, FileManager.default.isReadableFile(atPath: path) else {
            setStatus("Choose a readable RTL8814A firmware file before scanning or joining.")
            return nil
        }
        UserDefaults.standard.set(path, forKey: "firmwarePath")
        return path
    }

    private func runTool(_ name: String, arguments: [String], passphrase: String? = nil,
                         showOutput: Bool = true,
                         completion: @escaping (Int32, String) -> Void) {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/\(name)")
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            setBusy(false, status: "Missing bundled helper: \(name)")
            appendOutput("Build the app with scripts/package-macos.sh, then reopen it.\n")
            return
        }

        let process = Process()
        let output = Pipe()
        let diagnostics = Pipe()
        let input = Pipe()
        process.executableURL = helper
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = diagnostics
        process.standardInput = passphrase == nil ? FileHandle.nullDevice : input
        process.currentDirectoryURL = Bundle.main.bundleURL
        activeProcess = process
        outputPipe = output
        diagnosticsPipe = diagnostics
        outputLock.lock()
        capturedOutput.removeAll(keepingCapacity: true)
        outputLock.unlock()

        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            guard let self else { return }
            self.outputLock.lock()
            self.capturedOutput.append(data)
            self.outputLock.unlock()
            let text = String(decoding: data, as: UTF8.self)
            if showOutput {
                DispatchQueue.main.async { self.appendOutput(text) }
            }
        }
        diagnostics.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            let text = String(decoding: data, as: UTF8.self)
            DispatchQueue.main.async { self?.appendOutput(text) }
        }
        process.terminationHandler = { [weak self] terminated in
            output.fileHandleForReading.readabilityHandler = nil
            diagnostics.fileHandleForReading.readabilityHandler = nil
            let remainder = output.fileHandleForReading.readDataToEndOfFile()
            let diagnosticRemainder = diagnostics.fileHandleForReading.readDataToEndOfFile()
            let result: String
            if let self {
                self.outputLock.lock()
                self.capturedOutput.append(remainder)
                result = String(decoding: self.capturedOutput, as: UTF8.self)
                self.outputLock.unlock()
            } else {
                result = String(decoding: remainder, as: UTF8.self)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.activeProcess = nil
                self.outputPipe = nil
                self.diagnosticsPipe = nil
                if showOutput && !remainder.isEmpty {
                    self.appendOutput(String(decoding: remainder, as: UTF8.self))
                }
                if !diagnosticRemainder.isEmpty {
                    self.appendOutput(String(decoding: diagnosticRemainder, as: UTF8.self))
                }
                completion(terminated.terminationStatus, result)
            }
        }

        do {
            if let passphrase {
                var secret = Data(passphrase.utf8)
                secret.append(0x0a)
                input.fileHandleForWriting.write(secret)
                secret.resetBytes(in: 0..<secret.count)
                input.fileHandleForWriting.closeFile()
            }
            try process.run()
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            activeProcess = nil
            outputPipe = nil
            diagnosticsPipe = nil
            setBusy(false, status: "Could not start \(name): \(error.localizedDescription)")
        }
    }

    private func appendOutput(_ text: String) {
        guard !text.isEmpty else { return }
        outputView.textStorage?.append(NSAttributedString(string: text))
        outputView.scrollToEndOfDocument(nil)
    }

    private func setStatus(_ status: String) {
        statusLabel.stringValue = status
    }

    private func setBusy(_ busy: Bool, status: String) {
        scanButton.isEnabled = !busy
        joinButton.isEnabled = !busy && selectedAccessPoint?.ssid_hex.isEmpty == false &&
            regionPopup.indexOfSelectedItem > 0 && securityPopup.indexOfSelectedItem > 0
        stopButton.isEnabled = busy
        channelField.isEnabled = !busy
        dwellField.isEnabled = !busy
        firmwareField.isEnabled = !busy
        regionPopup.isEnabled = !busy && selectedAccessPoint != nil
        securityPopup.isEnabled = !busy && selectedAccessPoint != nil && securityPopup.numberOfItems > 1
        passphraseField.isEnabled = !busy && securityPopup.numberOfItems > 1
        setStatus(status)
    }

    private func updateSelectionControls() {
        let wasBusy = activeProcess != nil
        securityPopup.removeAllItems()
        securityPopup.addItem(withTitle: "Choose security…")
        if let ap = selectedAccessPoint {
            if ap.wpa2_psk { securityPopup.addItem(withTitle: "WPA2-PSK/CCMP") }
            if ap.sae { securityPopup.addItem(withTitle: "WPA3-SAE (H&P)") }
            if ap.sae && ap.sae_h2e { securityPopup.addItem(withTitle: "WPA3-SAE (H2E)") }
            regionPopup.isEnabled = true
            securityPopup.isEnabled = securityPopup.numberOfItems > 1
            passphraseField.isEnabled = securityPopup.numberOfItems > 1
            setStatus(ap.ssid_hex.isEmpty ?
                "Selected hidden AP \(ap.bssid). Enter a visible SSID before joining." :
                "Selected \(ap.displaySSID) (\(ap.bssid), channel \(ap.channel)). Choose region and security.")
        } else {
            regionPopup.isEnabled = false
            securityPopup.isEnabled = false
            passphraseField.isEnabled = false
            setStatus("Select an AP from the passive scan results.")
        }
        joinButton.isEnabled = !wasBusy && selectedAccessPoint?.ssid_hex.isEmpty == false &&
            regionPopup.indexOfSelectedItem > 0 && securityPopup.indexOfSelectedItem > 0
    }

    private func startJoin() {
        guard activeProcess == nil, let firmware = validatedFirmwarePath(), let ap = selectedAccessPoint else { return }
        guard regionPopup.indexOfSelectedItem > 0, securityPopup.indexOfSelectedItem > 0 else {
            setStatus("Choose both the regulatory region and security mode.")
            return
        }
        let password = passphraseField.stringValue
        guard (8...63).contains(password.utf8.count) else {
            setStatus("WPA2 / WPA3 passphrases must be 8–63 UTF-8 bytes.")
            return
        }
        let region = regionPopup.titleOfSelectedItem?.lowercased() ?? ""
        var arguments = [
            "--connect", "--ssid-hex", ap.ssid_hex, "--bssid", ap.bssid,
            "--channel", String(ap.channel), "--regd", region,
            "--fw", firmware, "--passphrase-stdin"
        ]
        let security = securityPopup.titleOfSelectedItem ?? ""
        if security == "WPA3-SAE (H&P)" {
            arguments.append("--sae")
        } else if security == "WPA3-SAE (H2E)" {
            arguments.append("--sae-h2e")
        }

        passphraseField.stringValue = ""
        appendOutput("Starting handshake to \(ap.displaySSID) at \(ap.bssid)…\n")
        setBusy(true, status: "Joining selected AP. This app checks the handshake only; IPv4 bridging is available through rtljoin --network.")
        runTool("rtljoin", arguments: arguments, passphrase: password) { [weak self] status, _ in
            guard let self else { return }
            self.setBusy(false, status: status == 0 ? "Handshake completed. The app did not enable IP forwarding." : "Join failed. See output below.")
            self.passphraseField.stringValue = ""
        }
    }

    @objc private func browseFirmware() {
        let panel = NSOpenPanel()
        panel.title = "Select RTL8814A firmware"
        panel.message = "Firmware is not bundled. Select a local rtw8814a_fw.bin file."
        panel.allowedContentTypes = [.data]
        panel.allowsOtherFileTypes = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        firmwareField.stringValue = url.path
        UserDefaults.standard.set(url.path, forKey: "firmwarePath")
    }

    @objc private func scanAction() {
        scanNetworks()
    }

    @objc private func joinAction() {
        startJoin()
    }

    @objc private func stopAction() {
        activeProcess?.terminate()
        setStatus("Stopping current operation…")
    }

    @objc private func selectionChanged() {
        let wasBusy = activeProcess != nil
        joinButton.isEnabled = !wasBusy && selectedAccessPoint?.ssid_hex.isEmpty == false &&
            regionPopup.indexOfSelectedItem > 0 && securityPopup.indexOfSelectedItem > 0
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        accessPoints.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard accessPoints.indices.contains(row), let identifier = tableColumn?.identifier.rawValue else { return nil }
        let ap = accessPoints[row]
        let value: String
        switch identifier {
        case "ssid": value = ap.displaySSID
        case "bssid": value = ap.bssid
        case "channel": value = String(ap.channel)
        case "rssi": value = "\(ap.rssi) dBm"
        default: value = ap.security
        }
        let cellID = NSUserInterfaceItemIdentifier("cell-\(identifier)")
        let cell = tableView.makeView(withIdentifier: cellID, owner: self) as? NSTableCellView ?? NSTableCellView()
        cell.identifier = cellID
        if cell.textField == nil {
            let label = NSTextField(labelWithString: "")
            label.lineBreakMode = .byTruncatingTail
            label.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(label)
            cell.textField = label
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
        }
        cell.textField?.stringValue = value
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateSelectionControls()
    }
}

private extension NSView {
    static func label(_ title: String) -> NSTextField {
        let label = NSTextField(labelWithString: title)
        label.setContentHuggingPriority(.required, for: .horizontal)
        return label
    }
}
