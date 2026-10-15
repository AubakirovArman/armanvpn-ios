// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var runner: MobileTunnelRunner?
    private var startup: Task<Void, Never>?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let runner = MobileTunnelRunner(provider: self)
        self.runner = runner
        startup = Task {
            do {
                guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
                      let config = proto.providerConfiguration,
                      let profileData = config["profile"] as? Data,
                      let certificate = config["certificate"] as? Data,
                      let cookie = options?["cookie"] as? String, !cookie.isEmpty,
                      let session = options?["session"] as? String, !session.isEmpty else {
                    throw MobileVPNError.message("Откройте armanVPN и подключитесь заново: нужна авторизация.")
                }
                let profile = try JSONDecoder().decode(MobileProfile.self, from: profileData)
                let port = (options?["tunnelPort"] as? NSNumber)?.uint16Value ?? UInt16(profile.port) ?? 443
                try await runner.start(profile: profile, certificate: certificate, port: port, session: session, cookie: cookie)
                try Task.checkCancellation()
                completionHandler(nil)
            } catch {
                await runner.stop(signout: true)
                completionHandler(error)
            }
        }
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        startup?.cancel()
        Task { await runner?.stop(signout: true); completionHandler() }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard messageData == Data("status".utf8) else { completionHandler?(nil); return }
        Task { completionHandler?(await runner?.status()) }
    }
}

private actor MobileTunnelRunner {
    private weak var provider: PacketTunnelProvider?
    private var channel: TLSChannel?
    private var gateway: MobileGateway?
    private var sessionID: String?
    private var receiveTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private var lifetimeTask: Task<Void, Never>?
    private var pathMonitor: NWPathMonitor?
    private var online: Bool?
    private var offlineSince: TimeInterval?
    private var lastReceived = ProcessInfo.processInfo.systemUptime
    private var started: Date?
    private var received: UInt64 = 0
    private var sent: UInt64 = 0
    private var stopped = false
    private var address = ""

    init(provider: PacketTunnelProvider) { self.provider = provider }

    func start(profile: MobileProfile, certificate: Data, port: UInt16, session: String, cookie: String) async throws {
        try profile.validate()
        guard try MobileCertificate(data: certificate).isCurrent else { throw MobileVPNError.message("Сертификат VPN больше не действует.") }
        let gateway = MobileGateway(profile: profile, certificate: certificate)
        self.gateway = gateway; sessionID = session
        let stream = try TLSChannel(host: profile.host, port: port, certificate: certificate)
        channel = stream
        try await stream.open()
        guard !stopped else { throw CancellationError() }
        let hello = CPWire.object("client_hello", [
            ("client_version", "2"), ("protocol_version", "2"),
            ("OM", CPWire.fields([("ipaddr", "0.0.0.0"), ("keep_address", "false")])),
            ("optional", CPWire.fields([("client_type", "4")])), ("cookie", CPWire.quote(cookie))
        ])
        try await stream.send(CPWire.control(hello))
        let (type, body) = try await stream.receive(timeout: 30)
        guard type == 1, let text = String(data: body, encoding: .utf8) else { throw MobileVPNError.message("Шлюз не подтвердил туннель.") }
        let reply = try CPExpression.parse(text)
        guard reply.name == "hello_reply" else { throw MobileVPNError.message("Шлюз отклонил создание SSL-туннеля.") }
        guard let office = reply.field("OM"), let ip = office.field("ipaddr")?.string,
              let numeric = IPv4Subnet.number(ip), numeric != 0 else { throw MobileVPNError.message("Шлюз не выдал IP-адрес.") }
        address = ip
        let mask = reply.at("optional", "subnet")?.string ?? "255.255.255.255"
        guard let maskNumber = IPv4Subnet.number(mask), maskNumber != 0,
              (~maskNumber & ((~maskNumber) &+ 1)) == 0 else { throw MobileVPNError.message("Неверная маска VPN-подсети.") }
        var routes: [IPv4Subnet]
        if let ranges = reply.field("range") { routes = try IPv4Subnet.fromRanges(ranges) }
        else { routes = try await gateway.routes(session: session) }
        if maskNumber != UInt32.max { routes.append(.init(address: IPv4Subnet.text(numeric & maskNumber), mask: mask)) }
        let dns = office.field("dns_servers")?.entries.compactMap(\.string).filter { IPv4Subnet.number($0) != nil } ?? []
        routes.append(contentsOf: dns.map { .init(address: $0, mask: "255.255.255.255") })
        guard !routes.isEmpty, routes.count <= 8192 else { throw MobileVPNError.message("Шлюз не выдал допустимые корпоративные маршруты.") }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.host)
        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: [mask])
        ipv4.includedRoutes = routes.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
        if IPv4Subnet.number(profile.host) != nil { ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: profile.host, subnetMask: "255.255.255.255")] }
        settings.ipv4Settings = ipv4; settings.mtu = 1350
        if !dns.isEmpty {
            let dnsSettings = NEDNSSettings(servers: dns)
            let domains = (office.field("dns_suffix")?.string ?? "").split(whereSeparator: { $0 == "," || $0 == ";" }).map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            dnsSettings.searchDomains = domains; dnsSettings.matchDomains = domains.isEmpty ? [""] : domains
            settings.dnsSettings = dnsSettings
        }
        guard let provider, !stopped else { throw CancellationError() }
        try await provider.setTunnelNetworkSettings(settings)
        guard !stopped else { throw CancellationError() }
        started = Date(); lastReceived = ProcessInfo.processInfo.systemUptime
        let interval = min(120, max(2, Double(reply.at("timeouts", "keepalive")?.string ?? "") ?? 20))
        let lifetime = Double(reply.at("timeouts", "authentication")?.string ?? "") ?? 0
        receiveTask = Task { await receiveLoop(stream) }
        keepaliveTask = Task { await keepaliveLoop(stream, interval: interval) }
        if lifetime > 60 {
            lifetimeTask = Task {
                do { try await Task.sleep(for: .seconds(lifetime - 30)); await fail("Истёк срок VPN-сессии на шлюзе. Подключитесь заново.") } catch { }
            }
        }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in Task { await self?.pathChanged(path.status == .satisfied) } }
        monitor.start(queue: DispatchQueue(label: "armanVPN.ios.path")); pathMonitor = monitor
        readPackets()
    }
    private func pathChanged(_ isOnline: Bool) {
        online = isOnline
        if isOnline { offlineSince = nil } else if offlineSince == nil { offlineSince = ProcessInfo.processInfo.systemUptime }
    }
    private func readPackets() {
        guard !stopped, let provider else { return }
        provider.packetFlow.readPackets { [weak self] packets, protocols in
            Task { await self?.sendPackets(packets, protocols: protocols) }
        }
    }
    private func sendPackets(_ packets: [Data], protocols: [NSNumber]) async {
        guard !stopped, let channel else { return }
        do {
            for (packet, proto) in zip(packets, protocols) where proto.int32Value == AF_INET {
                try await channel.send(CPWire.frame(type: 2, payload: packet), bounded: false); sent += UInt64(packet.count)
            }
            readPackets()
        } catch { await fail("Не удалось отправить данные в VPN: \(error.localizedDescription)") }
    }
    private func receiveLoop(_ channel: TLSChannel) async {
        do {
            while !Task.isCancelled && !stopped {
                let (kind, data) = try await channel.receive()
                lastReceived = ProcessInfo.processInfo.systemUptime
                if kind == 2 {
                    guard data.count >= 20, data.first.map({ $0 >> 4 == 4 }) == true else { throw MobileVPNError.message("Шлюз прислал неверный IP-пакет.") }
                    provider?.packetFlow.writePackets([data], withProtocols: [NSNumber(value: AF_INET)])
                    received += UInt64(data.count)
                } else if let text = String(data: data, encoding: .utf8) {
                    let control = try CPExpression.parse(text)
                    if control.name == "disconnect" { throw MobileVPNError.message("Шлюз прислал команду отключения VPN.") }
                }
            }
        } catch { if !stopped { await fail("SSL-соединение завершилось: \(error.localizedDescription)") } }
    }
    private func keepaliveLoop(_ channel: TLSChannel, interval: Double) async {
        do {
            while !Task.isCancelled && !stopped {
                let now = ProcessInfo.processInfo.systemUptime
                if let offlineSince, now - offlineSince > 10 { throw MobileVPNError.message("На iPhone отсутствует доступная сеть.") }
                if now - lastReceived >= interval * 3 { throw MobileVPNError.message("Шлюз не отвечает на keepalive более \(Int(interval * 3)) секунд.") }
                try await channel.send(CPWire.control(CPWire.object("keepalive", [("id", "0")])))
                try await Task.sleep(for: .seconds(interval))
            }
        } catch { if !stopped && !Task.isCancelled { await fail(error.localizedDescription) } }
    }
    private func fail(_ message: String) async {
        guard !stopped else { return }
        let provider = provider
        await stop(signout: false)
        provider?.cancelTunnelWithError(MobileVPNError.message(message))
    }
    func stop(signout: Bool) async {
        guard !stopped else { return }; stopped = true
        receiveTask?.cancel(); keepaliveTask?.cancel(); lifetimeTask?.cancel(); pathMonitor?.cancel()
        channel?.cancel(); channel = nil
        if signout, let gateway, let sessionID { await gateway.signout(session: sessionID) }
        gateway = nil; sessionID = nil
    }
    func status() -> Data? {
        try? JSONSerialization.data(withJSONObject: ["connectedSince": started.map { ISO8601DateFormatter().string(from: $0) } ?? "", "received": received,
            "sent": sent, "address": address, "network": online.map { $0 ? "Доступна" : "Нет сети" } ?? "Проверяется",
            "lastReplySeconds": Int(max(0, ProcessInfo.processInfo.systemUptime - lastReceived)), "transport": "SSL / TCP"])
    }
}
