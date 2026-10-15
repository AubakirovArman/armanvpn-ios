import Combine
import Foundation
import NetworkExtension
import UIKit

@MainActor
final class MobileVPNModel: ObservableObject {
    static let providerID = "armanibadboy.armanVPN-IOS.PacketTunnel"
    @Published var profile = MobileProfile()
    @Published var password = ""
    @Published var phase = "Отключено"
    @Published var busy = false
    @Published var connected = false
    @Published var error: String?
    @Published var pendingCertificate: MobileCertificate?
    @Published var challenge: String?
    @Published var challengeAnswer = ""
    @Published var options: [MobileLoginOption] = []
    @Published var events: [String] = []
    @Published var received: UInt64 = 0
    @Published var sent: UInt64 = 0
    @Published var address = ""
    @Published var network = "Проверяется"
    @Published var lastReplySeconds = 0
    @Published var connectedSince: Date?
    @Published var testStarted: Date?
    @Published var testResult: String?
    private var manager: NETunnelProviderManager?
    private var monitor: Task<Void, Never>?
    private var operation: Task<Void, Never>?
    private var acceptedCertificate: MobileCertificate?
    private var acceptedEndpoint: String?
    private var pendingAuth: (MobileGateway, MobileAuthReply, UInt16)?
    private var previousStatus: NEVPNStatus = .invalid
    private var testSession: Date?
    private var manuallyStopped = false
    private var generation = UUID()

    init() {
        if let data = UserDefaults.standard.data(forKey: "profile"), let profile = try? JSONDecoder().decode(MobileProfile.self, from: data) { self.profile = profile }
        monitor = Task { [weak self] in
            await self?.loadManager()
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
    deinit { monitor?.cancel(); operation?.cancel() }

    func saveProfile() {
        profile.host = profile.host.trimmingCharacters(in: .whitespacesAndNewlines)
        profile.username = profile.username.trimmingCharacters(in: .whitespacesAndNewlines)
        if let data = try? JSONEncoder().encode(profile) { UserDefaults.standard.set(data, forKey: "profile") }
    }
    func rememberPassword(_ value: Bool) {
        profile.rememberPassword = value
        do {
            if value && !password.isEmpty { try MobileVault.save(password, account: profile.account) }
            if !value { try MobileVault.delete(profile.account) }
            saveProfile()
        } catch { report(error) }
    }
    func connect() {
        guard !busy, !connected, pendingCertificate == nil, challenge == nil else { return }
        saveProfile(); error = nil; manuallyStopped = false
        perform { try await self.prepareAndConnect() }
    }
    private func prepareAndConnect() async throws {
        try profile.validate()
        guard !profile.username.isEmpty else { throw MobileVPNError.message("Введите логин VPN.") }
        phase = "Проверка сертификата"
        let candidate = try await MobileGateway.inspect(profile)
        try Task.checkCancellation()
        guard candidate.isCurrent else { throw MobileVPNError.message("Сертификат шлюза истёк или ещё не действует.") }
        let saved = UserDefaults.standard.data(forKey: "certificate:" + profile.endpoint)
        let accepted = acceptedEndpoint == profile.endpoint && acceptedCertificate?.data == candidate.data
        guard accepted || saved == candidate.data else {
            pendingCertificate = candidate; phase = "Подтвердите сертификат"; return
        }
        acceptedCertificate = candidate; acceptedEndpoint = profile.endpoint
        let gateway = MobileGateway(profile: profile, certificate: candidate.data)
        phase = "Параметры шлюза"
        let information = try await gateway.information(); options = information.options
        guard !options.isEmpty else { throw MobileVPNError.message("Шлюз не предоставил способы входа.") }
        if !options.contains(where: { $0.id == profile.loginType }) { profile.loginType = options[0].id; saveProfile() }
        let gatewayForLogin = MobileGateway(profile: profile, certificate: candidate.data)
        if password.isEmpty && profile.rememberPassword { password = try MobileVault.password(profile.account) ?? "" }
        guard !password.isEmpty else { throw MobileVPNError.message("Введите пароль VPN.") }
        if profile.rememberPassword { try MobileVault.save(password, account: profile.account) }
        phase = "Авторизация"
        var reply = try await gatewayForLogin.authenticate()
        if reply.cookie == nil {
            if reply.prompt?.hasPrefix("https://") == true { throw MobileVPNError.message("Этот способ входа требует SSO. Выберите вход по логину и паролю.") }
            reply = try await gatewayForLogin.challenge(session: reply.session, answer: password)
        }
        try Task.checkCancellation()
        try await continueAuth(gateway: gatewayForLogin, reply: reply, port: information.tunnelPort)
    }
    func acceptCertificate(remember: Bool) {
        guard let certificate = pendingCertificate else { return }
        acceptedCertificate = certificate; acceptedEndpoint = profile.endpoint
        if remember { UserDefaults.standard.set(certificate.data, forKey: "certificate:" + profile.endpoint) }
        pendingCertificate = nil; event("Сертификат принят пользователем.")
        perform { try await self.prepareAndConnect() }
    }
    func rejectCertificate() {
        pendingCertificate = nil; acceptedCertificate = nil; acceptedEndpoint = nil; phase = "Сертификат не принят"
        event("Подключение отменено пользователем.")
    }
    private func continueAuth(gateway: MobileGateway, reply: MobileAuthReply, port: UInt16) async throws {
        guard let cookie = reply.cookie else {
            guard reply.prompt?.hasPrefix("https://") != true else { throw MobileVPNError.message("Вход через SSO пока не поддерживается.") }
            pendingAuth = (gateway, reply, port); challenge = reply.prompt ?? "Введите код подтверждения"
            phase = "Ожидается подтверждение"; return
        }
        phase = "Разрешение VPN в iOS"
        do {
            let current = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerID; proto.serverAddress = gateway.profile.endpoint; proto.disconnectOnSleep = false
            proto.providerConfiguration = ["profile": try JSONEncoder().encode(gateway.profile), "certificate": gateway.certificate]
            current.protocolConfiguration = proto; current.localizedDescription = "armanVPN — сеть Армана"
            current.isEnabled = true; current.isOnDemandEnabled = false
            try await current.saveToPreferences()
            try await current.loadFromPreferences()
            try Task.checkCancellation()
            manager = current; pendingAuth = nil
            guard let session = current.connection as? NETunnelProviderSession else { throw MobileVPNError.message("Не удалось создать VPN-сессию iOS.") }
            try session.startTunnel(options: ["cookie": cookie as NSString, "session": reply.session as NSString, "tunnelPort": NSNumber(value: port)])
            phase = "Подключение"
            event("iOS запускает SSL-туннель.")
        } catch {
            await gateway.signout(session: reply.session)
            throw error
        }
    }
    func sendChallenge() {
        guard let pendingAuth, !challengeAnswer.isEmpty, !busy else { return }
        let answer = challengeAnswer; challengeAnswer = ""; challenge = nil
        perform {
            let reply = try await pendingAuth.0.challenge(session: pendingAuth.1.session, answer: answer)
            try await self.continueAuth(gateway: pendingAuth.0, reply: reply, port: pendingAuth.2)
        }
    }
    func disconnect() {
        manuallyStopped = true; generation = UUID(); operation?.cancel(); operation = nil; busy = false
        let abandonedAuth = pendingAuth
        pendingCertificate = nil; challenge = nil; pendingAuth = nil
        (manager?.connection as? NETunnelProviderSession)?.stopTunnel()
        phase = manager?.connection.status == .connected || manager?.connection.status == .connecting ? "Отключение" : "Отключено"
        if let abandonedAuth { Task { await abandonedAuth.0.signout(session: abandonedAuth.1.session) } }
        if testStarted != nil { finishTest("Тест остановлен пользователем.") }
        event("Запрошено отключение VPN.")
    }
    func startTest() {
        guard connected, testStarted == nil else { return }
        testStarted = Date(); testSession = connectedSince; testResult = nil
        event("Начат тест: 10 минут одной VPN-сессии.")
    }
    private func finishTest(_ result: String) { testResult = result; testStarted = nil; testSession = nil; event(result) }
    private func loadManager() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerID
            }
        } catch { report(error) }
    }
    func refresh() async {
        guard let manager else { return }
        let status = manager.connection.status
        let changed = previousStatus != status
        if changed && previousStatus == .connected && status != .connected && testStarted != nil {
            finishTest("Тест не пройден: VPN-соединение прервалось.")
        }
        previousStatus = status; connected = status == .connected
        connectedSince = manager.connection.connectedDate
        if !busy && pendingCertificate == nil && challenge == nil {
            switch status {
            case .connected: phase = "Подключено"
            case .connecting: phase = "Подключение"
            case .reasserting: phase = "Восстановление соединения"
            case .disconnecting: phase = "Отключение"
            default: phase = "Отключено"
            }
        }
        if changed && status == .connected { error = nil; event("Подключено: SSL / TCP.") }
        if changed && status == .disconnected && !manuallyStopped {
            manager.connection.fetchLastDisconnectError { [weak self] failure in
                guard let failure else { return }
                Task { @MainActor in self?.report(failure) }
            }
        }
        if connected, let session = manager.connection as? NETunnelProviderSession {
            do {
                let data: Data? = try await withCheckedThrowingContinuation { continuation in
                    let reply = ProviderMessageReply(continuation)
                    do { try session.sendProviderMessage(Data("status".utf8)) { reply.finish(.success($0)) } }
                    catch { reply.finish(.failure(error)) }
                    DispatchQueue.global().asyncAfter(deadline: .now() + 5) { reply.finish(.success(nil)) }
                }
                if let data, let info = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    received = (info["received"] as? NSNumber)?.uint64Value ?? 0; sent = (info["sent"] as? NSNumber)?.uint64Value ?? 0
                    address = info["address"] as? String ?? ""; network = info["network"] as? String ?? "Проверяется"
                    lastReplySeconds = info["lastReplySeconds"] as? Int ?? 0
                }
            } catch { self.error = "Не удалось получить диагностику VPN-расширения." }
        }
        if let testStarted {
            if connectedSince != testSession { finishTest("Тест не пройден: VPN-сессия изменилась.") }
            else if connected && Date().timeIntervalSince(testStarted) >= 600 { finishTest("Тест пройден: 10 минут без разрывов и переподключений.") }
        }
    }
    private func perform(_ action: @escaping @MainActor () async throws -> Void) {
        guard !busy else { return }; busy = true; error = nil
        let token = UUID(); generation = token
        operation = Task {
            defer { if generation == token { busy = false } }
            do { try await action() }
            catch is CancellationError { }
            catch { if generation == token { phase = "Не удалось подключиться"; report(error) } }
        }
    }
    private func report(_ failure: Error) {
        error = failure.localizedDescription.replacingOccurrences(of: password.isEmpty ? "\0" : password, with: "••••••")
        event(error ?? "Ошибка VPN.")
    }
    private func event(_ message: String) {
        events.insert(Date().formatted(date: .omitted, time: .standard) + "  " + message, at: 0)
        if events.count > 100 { events.removeLast(events.count - 100) }
    }
    func copyFeedback() {
        UIPasteboard.general.string = "armanVPN iOS 1.0\niOS: \(UIDevice.current.systemVersion)\nСостояние: \(phase)\nТранспорт: SSL / TCP\nТест: \(testResult ?? "Не завершён")\nОшибка: \(error ?? "Нет")\nЧто произошло:\n"
    }
}

private final class ProviderMessageReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Error>?
    init(_ continuation: CheckedContinuation<Data?, Error>) { self.continuation = continuation }
    func finish(_ result: Result<Data?, Error>) {
        lock.lock(); let continuation = self.continuation; self.continuation = nil; lock.unlock()
        continuation?.resume(with: result)
    }
}
