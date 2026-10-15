// Check Point CCC / SLIM interoperability, derived from snx-rs 6.5.1.
// Copyright Dmitry Pankratov and contributors. Adaptations: armanVPN.
// SPDX-License-Identifier: AGPL-3.0-only
import Foundation

enum MobileVPNError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}

indirect enum CPExpression {
    case atom(String)
    case list([CPExpression])

    var values: [CPExpression] { if case .list(let values) = self { return values }; return [] }
    var string: String? {
        if case .atom(let value) = self { return value }
        if values.count == 1 { return values.first?.string }
        return nil
    }
    var name: String? { values.first?.string }
    func field(_ key: String) -> CPExpression? {
        let items = values
        for i in items.indices.dropLast() {
            if case .atom(":" + key) = items[i] { return items[i + 1] }
        }
        return nil
    }
    func at(_ path: String...) -> CPExpression? {
        path.reduce(Optional(self)) { $0?.field($1) }
    }
    var entries: [CPExpression] {
        let items = values
        return items.indices.dropLast().compactMap {
            if case .atom(":") = items[$0] { return items[$0 + 1] }; return nil
        }
    }

    static func parse(_ text: String) throws -> Self {
        guard text.utf8.count <= 1_000_000 else { throw MobileVPNError.message("Слишком большой ответ шлюза.") }
        let chars = Array(text.trimmingCharacters(in: CharacterSet(charactersIn: "\0").union(.whitespacesAndNewlines)))
        var index = 0
        func skip() { while index < chars.count && chars[index].isWhitespace { index += 1 } }
        func read(_ depth: Int) throws -> Self {
            guard depth < 64 else { throw MobileVPNError.message("Слишком вложенный ответ шлюза.") }
            skip()
            guard index < chars.count else { throw MobileVPNError.message("Неполный ответ шлюза.") }
            if chars[index] == "(" {
                index += 1
                var children: [Self] = []
                while true {
                    skip()
                    guard index < chars.count else { throw MobileVPNError.message("Неполный ответ шлюза.") }
                    if chars[index] == ")" { index += 1; return .list(children) }
                    children.append(try read(depth + 1))
                }
            }
            var value = ""
            if chars[index] == "\"" {
                index += 1
                while index < chars.count {
                    let character = chars[index]; index += 1
                    if character == "\"" { return .atom(value) }
                    if character == "\\" {
                        guard index < chars.count else { break }
                        value.append(chars[index]); index += 1
                    } else { value.append(character) }
                }
                throw MobileVPNError.message("Незакрытая строка шлюза.")
            }
            while index < chars.count && !chars[index].isWhitespace && chars[index] != "(" && chars[index] != ")" {
                value.append(chars[index]); index += 1
            }
            guard !value.isEmpty else { throw MobileVPNError.message("Неверный формат ответа шлюза.") }
            return .atom(value)
        }
        let result = try read(0); skip()
        guard index == chars.count else { throw MobileVPNError.message("Лишние данные в ответе шлюза.") }
        return result
    }
}

enum CPWire {
    private static let xor: [UInt8] = [45,79,68,73,70,73,69,68,38,87,48,82,79,80,69,82,84,89,51,72,69,69,84,55,73,84,72,47,43,52,72,69,51,72,69,69,84,41,36,51,63,44,36,33,48,63,33,53,63,48,50,47,48,37,50,52,41,37,51,46,53,44,44,16,38,55,63,55,48,63,47,34,42,37,35,52,51]
    static func obfuscate(_ text: String) -> String {
        Array(text.utf8).enumerated().reversed().map { index, byte in
            let v = (byte % 255) ^ xor[index % xor.count]
            return String(format: "%02x", v == 0 ? 255 : v)
        }.joined()
    }
    static func deobfuscate(_ text: String) throws -> String {
        let chars = Array(text.utf8)
        guard chars.count % 2 == 0 else { throw MobileVPNError.message("Неверная кодировка ответа шлюза.") }
        var bytes: [UInt8] = []
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(bytes: chars[i...i+1], encoding: .utf8) ?? "", radix: 16) else {
                throw MobileVPNError.message("Неверная кодировка ответа шлюза.")
            }
            bytes.append(byte)
        }
        let decoded: [UInt8] = bytes.reversed().enumerated().map { index, byte in
            let v = (byte % 255) ^ xor[index % xor.count]; return v == 0 ? 255 : v
        }
        guard let result = String(bytes: decoded, encoding: .utf8) else { throw MobileVPNError.message("Неверный текст шлюза.") }
        return result
    }
    static func quote(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
    static func fields(_ fields: [(String, String)]) -> String {
        fields.sorted { $0.0 < $1.0 }.map { key, value in
            if value.hasPrefix(":") || value.hasPrefix("(") {
                return ":\(key) (\n" + value.split(separator: "\n", omittingEmptySubsequences: false).map { "\t" + $0 }.joined(separator: "\n") + ")"
            }
            return ":\(key) (\(value))"
        }.joined(separator: "\n")
    }
    static func object(_ name: String, _ fields: [(String, String)]) -> String {
        "(\(name)\n" + self.fields(fields).split(separator: "\n", omittingEmptySubsequences: false).map { "\t" + $0 }.joined(separator: "\n") + ")"
    }
    static func ccc(type: String, id: Int, session: String? = nil, data: String, version: Int? = nil) -> String {
        var header = [("id", String(id)), ("type", type)]
        if let session { header.append(("session_id", quote(session))) }
        if let version { header.append(("protocol_version", String(version))) }
        return object("CCCclientRequest", [("RequestData", data), ("RequestHeader", fields(header))])
    }
    static func frame(type: UInt32, payload: Data) throws -> Data {
        guard payload.count <= 1_000_000, type == 1 || type == 2 else { throw MobileVPNError.message("Неверный пакет VPN.") }
        var length = UInt32(payload.count).bigEndian; var kind = type.bigEndian
        var result = withUnsafeBytes(of: &length) { Data($0) }
        result.append(withUnsafeBytes(of: &kind) { Data($0) }); result.append(payload)
        return result
    }
    static func control(_ text: String) throws -> Data { try frame(type: 1, payload: Data(text.utf8) + Data([0])) }
}

struct IPv4Subnet: Equatable {
    let address: String
    let mask: String
    static func number(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts { guard let byte = UInt8(part) else { return nil }; result = (result << 8) | UInt32(byte) }
        return result
    }
    static func text(_ value: UInt32) -> String { [24,16,8,0].map { String((value >> $0) & 255) }.joined(separator: ".") }
    static func covering(from: String, to: String) throws -> [Self] {
        guard let low = number(from), let high = number(to), low <= high else { throw MobileVPNError.message("Шлюз прислал неверную подсеть.") }
        // Match snx-rs: the gateway uses 0.0.0.1 as a full-tunnel sentinel.
        if low == 1 { return [] }
        var start = UInt64(low); let end = UInt64(high)
        var result: [Self] = []
        while start <= end {
            var bits = start == 0 ? 32 : min(32, start.trailingZeroBitCount)
            while (UInt64(1) << bits) > end - start + 1 { bits -= 1 }
            let mask = bits == 32 ? UInt32(0) : UInt32.max << bits
            result.append(Self(address: text(UInt32(start)), mask: text(mask)))
            start += UInt64(1) << bits
        }
        return result
    }
    static func fromRanges(_ node: CPExpression) throws -> [Self] {
        try node.entries.flatMap { entry in
            guard let low = entry.field("from")?.string, let high = entry.field("to")?.string else {
                throw MobileVPNError.message("Шлюз прислал неполную подсеть.")
            }
            return try covering(from: low, to: high)
        }
    }
}

struct MobileProfile: Codable, Equatable {
    var host = ""
    var port = "443"
    var username = ""
    var loginType = ""
    var rememberPassword = false
    var endpoint: String { host.lowercased() + (port == "443" ? "" : ":" + port) }
    var account: String { endpoint + "|" + username }
    func validate() throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        guard !host.isEmpty, host.count <= 253, host.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              !host.hasPrefix("."), !host.hasSuffix("."), !host.hasPrefix("-"), !host.hasSuffix("-"),
              !host.contains(".."), let port = UInt16(port), port > 0 else { throw MobileVPNError.message("Проверьте адрес сервера и порт.") }
    }
}
