// SPDX-License-Identifier: AGPL-3.0-only
import Foundation
import Network
import Security

final class TLSChannel: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "armanVPN.ios.tls")

    init(host: String, port: UInt16, certificate: Data) throws {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { throw MobileVPNError.message("Неверный порт VPN.") }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let trust = sec_trust_copy_ref(trust).takeRetainedValue()
            complete(MobileCertificate.approve(trust, expected: certificate))
        }, queue)
        let tcp = NWProtocolTCP.Options(); tcp.noDelay = true
        connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: NWParameters(tls: tls, tcp: tcp))
    }

    func open() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = CompletionGate(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: once.finish(.success(()))
                case .failed(let error): once.finish(.failure(error))
                case .cancelled: once.finish(.failure(CancellationError()))
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 30) { [connection] in
                if once.finish(.failure(MobileVPNError.message("Истекло время подключения к VPN-шлюзу."))) { connection.cancel() }
            }
        }
    }
    func send(_ data: Data, bounded: Bool = true) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let once = CompletionGate(continuation)
            connection.send(content: data, completion: .contentProcessed { error in
                once.finish(error.map { .failure($0) } ?? .success(()))
            })
            if bounded {
                queue.asyncAfter(deadline: .now() + 30) { [connection] in
                    if once.finish(.failure(MobileVPNError.message("Истекло время отправки данных в VPN."))) { connection.cancel() }
                }
            }
        }
    }
    private func readExactly(_ count: Int) async throws -> Data {
        var output = Data()
        while output.count < count {
            let remaining = count - output.count
            let part: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: remaining, maximumLength: remaining) { data, _, complete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data, !data.isEmpty { continuation.resume(returning: data) }
                    else { continuation.resume(throwing: MobileVPNError.message(complete ? "Шлюз закрыл SSL-соединение." : "Пустой ответ VPN-шлюза.")) }
                }
            }
            output.append(part)
        }
        return output
    }
    func receive(timeout: Int? = nil) async throws -> (UInt32, Data) {
        let deadline = ReceiveDeadline()
        defer { deadline.disarm() }
        if let timeout {
            queue.asyncAfter(deadline: .now() + .seconds(timeout)) { [connection] in
                if deadline.expire() { connection.cancel() }
            }
        }
        let header = try await readExactly(8)
        let length = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let kind = header.suffix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= 1_000_000, kind == 1 || kind == 2 else { throw MobileVPNError.message("Шлюз прислал некорректный пакет VPN.") }
        return (kind, try await readExactly(Int(length)))
    }
    func cancel() { connection.cancel() }
}

private final class ReceiveDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = true
    func disarm() { lock.lock(); armed = false; lock.unlock() }
    func expire() -> Bool { lock.lock(); defer { lock.unlock() }; let result = armed; armed = false; return result }
}

private final class CompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    init(_ continuation: CheckedContinuation<Void, Error>) { self.continuation = continuation }
    @discardableResult func finish(_ result: Result<Void, Error>) -> Bool {
        lock.lock(); let value = continuation; continuation = nil; lock.unlock()
        guard let value else { return false }; value.resume(with: result); return true
    }
}
