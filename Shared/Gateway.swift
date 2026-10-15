// SPDX-License-Identifier: AGPL-3.0-only
import CryptoKit
import Foundation
import Security

struct MobileCertificate: Identifiable {
    let data: Data
    let subject: String
    let notBefore: Date
    let expires: Date
    var fingerprint: String { SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined(separator: ":") }
    var id: String { fingerprint }
    var isCurrent: Bool { notBefore <= Date() && Date() < expires }

    init(data: Data) throws {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else { throw MobileVPNError.message("Неверный сертификат.") }
        self.data = data
        subject = SecCertificateCopySubjectSummary(certificate) as String? ?? "Сертификат VPN"
        let root = try DERNode.read(data)
        guard let tbs = try root.children().first else { throw MobileVPNError.message("Неполный сертификат.") }
        let fields = try tbs.children()
        let offset = fields.first?.tag == 0xa0 ? 1 : 0
        guard fields.count > offset + 3 else { throw MobileVPNError.message("Нет срока действия сертификата.") }
        let validity = try fields[offset + 3].children()
        guard validity.count == 2, let start = validity[0].date, let end = validity[1].date else {
            throw MobileVPNError.message("Неизвестен срок действия сертификата.")
        }
        notBefore = start; expires = end
    }

    static func approve(_ trust: SecTrust, expected: Data) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
              SecCertificateCopyData(leaf) as Data == expected,
              let info = try? Self(data: expected), info.isCurrent else { return false }
        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetAnchorCertificates(trust, [leaf] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetPolicies(trust, SecPolicyCreateBasicX509())
        return SecTrustEvaluateWithError(trust, nil)
    }
}

private struct DERNode {
    let tag: UInt8
    let content: Data
    static func read(_ data: Data) throws -> Self {
        var index = 0; let bytes = Array(data)
        let node = try read(bytes, &index)
        guard index == bytes.count else { throw MobileVPNError.message("Лишние данные сертификата.") }
        return node
    }
    private static func read(_ bytes: [UInt8], _ index: inout Int) throws -> Self {
        guard index + 2 <= bytes.count else { throw MobileVPNError.message("Неполный сертификат.") }
        let tag = bytes[index]; index += 1
        let first = Int(bytes[index]); index += 1
        var length = first
        if first & 0x80 != 0 {
            let count = first & 0x7f
            guard count > 0, count <= 4, index + count <= bytes.count else { throw MobileVPNError.message("Неверная длина сертификата.") }
            length = 0
            for _ in 0..<count { length = (length << 8) | Int(bytes[index]); index += 1 }
        }
        guard length <= bytes.count - index else { throw MobileVPNError.message("Неполный сертификат.") }
        let content = Data(bytes[index..<index + length]); index += length
        return Self(tag: tag, content: content)
    }
    func children() throws -> [Self] {
        let bytes = Array(content); var index = 0; var result: [Self] = []
        while index < bytes.count { result.append(try Self.read(bytes, &index)) }
        return result
    }
    var date: Date? {
        guard (tag == 0x17 || tag == 0x18), let text = String(data: content, encoding: .ascii) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.isLenient = false
        formatter.dateFormat = tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
        // RFC 5280 UTCTime uses 1950–2049, independently of the current century.
        if tag == 0x17 { formatter.twoDigitStartDate = Date(timeIntervalSince1970: -631_152_000) }
        return formatter.date(from: text)
    }
}

private final class MobileTrustDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var captured: Data?
    let approved: Data?
    init(approved: Data?) { self.approved = approved }
    var certificate: Data? { lock.lock(); defer { lock.unlock() }; return captured }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        lock.lock(); captured = SecCertificateCopyData(leaf) as Data; lock.unlock()
        guard let approved, MobileCertificate.approve(trust, expected: approved) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}

struct MobileLoginOption: Identifiable { let id: String; let title: String }
struct MobileGatewayInfo { let options: [MobileLoginOption]; let tunnelPort: UInt16 }
struct MobileAuthReply {
    let session: String
    let cookie: String?
    let prompt: String?
}

struct MobileGateway {
    private static let sequence = CCCRequestSequence()
    let profile: MobileProfile
    let certificate: Data

    private static func makeSession(_ delegate: MobileTrustDelegate) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 60
        config.tlsMinimumSupportedProtocolVersion = .TLSv12; config.tlsMaximumSupportedProtocolVersion = .TLSv12
        config.connectionProxyDictionary = [:]; config.urlCache = nil; config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }
    private static func url(_ profile: MobileProfile) throws -> URL {
        try profile.validate()
        var parts = URLComponents(); parts.scheme = "https"; parts.host = profile.host
        parts.port = Int(profile.port); parts.path = "/clients/"
        guard let url = parts.url else { throw MobileVPNError.message("Неверный адрес VPN.") }; return url
    }
    static func inspect(_ profile: MobileProfile) async throws -> MobileCertificate {
        let delegate = MobileTrustDelegate(approved: nil); let session = makeSession(delegate)
        defer { session.invalidateAndCancel() }
        do { _ = try await session.data(from: url(profile)) }
        catch { if let data = delegate.certificate { return try MobileCertificate(data: data) }; throw error }
        guard let data = delegate.certificate else { throw MobileVPNError.message("Шлюз не предоставил сертификат.") }
        return try MobileCertificate(data: data)
    }
    func request(type: String, data: String, sessionID: String? = nil, version: Int? = nil, timeout: TimeInterval = 60) async throws -> CPExpression {
        guard try MobileCertificate(data: certificate).isCurrent else { throw MobileVPNError.message("Сертификат VPN истёк или ещё не действует.") }
        let delegate = MobileTrustDelegate(approved: certificate); let session = Self.makeSession(delegate)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: try Self.url(profile)); request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(CPWire.ccc(type: type, id: Self.sequence.next(), session: sessionID, data: data, version: version).utf8)
        let (body, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
              let text = String(data: body, encoding: .utf8) else { throw MobileVPNError.message("Шлюз отклонил запрос \(type).") }
        let reply = try CPExpression.parse(text)
        _ = try Self.responseData(reply, request: type)
        return reply
    }
    static func responseData(_ reply: CPExpression, request: String) throws -> CPExpression {
        // CCC uses 600 for success; this is not an HTTP status code.
        guard reply.name == "CCCserverResponse", reply.at("ResponseHeader", "return_code")?.string == "600",
              let data = reply.field("ResponseData"), !data.values.isEmpty else {
            let code = Int(reply.at("ResponseHeader", "return_code")?.string ?? "").map(String.init) ?? "нет"
            throw MobileVPNError.message("Шлюз вернул ошибку \(request) (код CCC: \(code), тип: \(String((reply.name ?? "нет").prefix(40)))).")
        }
        return data
    }
    func information() async throws -> MobileGatewayInfo {
        let info = CPWire.fields([("client_type", "TRAC"), ("client_version", "1"), ("client_support_saml", "true")])
        let reply = try await request(type: "ClientHello", data: CPWire.fields([("client_info", info)]))
        guard let data = reply.field("ResponseData") else { throw MobileVPNError.message("Нет параметров шлюза.") }
        func options(_ node: CPExpression) -> [MobileLoginOption] {
            if let id = node.field("id")?.string, let title = node.field("display_name")?.string { return [.init(id: id, title: title)] }
            return node.values.flatMap(options)
        }
        let port = UInt16(data.at("connectivity_info", "tcpt_port")?.string ?? "") ?? UInt16(profile.port) ?? 443
        return .init(options: options(data), tunnelPort: port)
    }
    func authenticate() async throws -> MobileAuthReply {
        let logging = CPWire.fields([("os_name", "Windows"), ("device_id", CPWire.quote("{" + UUID().uuidString + "}"))])
        // TRAC compatibility matches the desktop engine. The gateway selects the login factors.
        let data = CPWire.fields([("client_type", "TRAC"), ("username", CPWire.obfuscate(profile.username)),
                                  ("password", ""), ("selectedLoginOption", CPWire.quote(profile.loginType)), ("client_logging_data", logging)])
        return try decodeAuth(await request(type: "UserPass", data: data))
    }
    func challenge(session: String, answer: String) async throws -> MobileAuthReply {
        let data = CPWire.fields([("client_type", "TRAC"), ("auth_session_id", CPWire.quote(session)), ("user_input", CPWire.obfuscate(answer))])
        return try decodeAuth(await request(type: "MultiChallange", data: data, sessionID: session))
    }
    private func decodeAuth(_ reply: CPExpression) throws -> MobileAuthReply {
        guard let data = reply.field("ResponseData"), let session = data.field("session_id")?.string ?? reply.at("ResponseHeader", "session_id")?.string,
              !session.isEmpty else { throw MobileVPNError.message("Шлюз не выдал сессию авторизации.") }
        if data.field("authn_status")?.string == "continue" {
            let prompt = try data.field("prompt")?.string.map(CPWire.deobfuscate) ?? "Введите код подтверждения"
            return .init(session: session, cookie: nil, prompt: prompt)
        }
        guard data.field("authn_status")?.string == "done", data.field("is_authenticated")?.string == "true",
              let key = data.field("active_key")?.string else { throw MobileVPNError.message("Шлюз отклонил вход. Проверьте логин, пароль и способ входа.") }
        let cookie = try CPWire.deobfuscate(key)
        guard !cookie.isEmpty else { throw MobileVPNError.message("Шлюз не выдал ключ VPN.") }
        return .init(session: session, cookie: cookie, prompt: nil)
    }
    func routes(session: String) async throws -> [IPv4Subnet] {
        let policies = CPWire.fields([("range", "")])
        let settings = CPWire.object("ClientSettings", [("requested_policies_and_current_versions", policies)])
        let reply = try await request(type: "ClientSettings", data: settings, sessionID: session, version: 100)
        guard let ranges = reply.at("ResponseData", "updated_policies", "range")?.field("settings") else { throw MobileVPNError.message("Шлюз не выдал корпоративные маршруты.") }
        return try IPv4Subnet.fromRanges(ranges)
    }
    func signout(session: String) async { _ = try? await request(type: "Signout", data: "", sessionID: session, version: 100, timeout: 3) }
}

private final class CCCRequestSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; value = value >= Int(UInt32.max) ? 1 : value + 1; return value }
}
