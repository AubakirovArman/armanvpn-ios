import Foundation
import XCTest
@testable import ArmanVPNMobileCore

final class ProtocolTests: XCTestCase {
    func testHelloReplyFromPinnedUpstream() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "hello_reply", withExtension: "txt", subdirectory: "Fixtures"))
        let hello = try CPExpression.parse(String(contentsOf: url, encoding: .utf8))
        XCTAssertEqual(hello.name, "hello_reply")
        XCTAssertEqual(hello.at("OM", "ipaddr")?.string, "10.0.0.10")
        XCTAssertEqual(hello.at("OM", "dns_servers")?.entries.compactMap(\.string), ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(hello.at("timeouts", "keepalive")?.string, "20")
        let routes = try IPv4Subnet.fromRanges(XCTUnwrap(hello.field("range")))
        XCTAssertEqual(routes, [.init(address: "10.0.0.0", mask: "255.0.0.0"), .init(address: "172.16.0.0", mask: "255.255.0.0")])
    }
    func testClientSettingsFromPinnedUpstream() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "client_settings", withExtension: "txt", subdirectory: "Fixtures"))
        let response = try CPExpression.parse(String(contentsOf: url, encoding: .utf8))
        _ = try MobileGateway.responseData(response, request: "ClientSettings")
        let settings = try XCTUnwrap(response.at("ResponseData", "updated_policies", "range")?.field("settings"))
        XCTAssertFalse(try IPv4Subnet.fromRanges(settings).isEmpty)
    }
    func testCCCObfuscationMatchesUpstreamWireFixture() throws {
        XCTAssertEqual(CPWire.obfuscate("testuser"), "36203a333d372a59")
        for value in ["foo", "", "test-only-password!", "Арман", "quote\"\\value"] {
            XCTAssertEqual(try CPWire.deobfuscate(CPWire.obfuscate(value)), value)
        }
        XCTAssertThrowsError(try CPWire.deobfuscate("xyz"))
    }
    func testParserRejectsMalformedAndDeepInput() {
        for text in ["(hello", "(hello) extra", "(hello :x (\"unterminated))", String(repeating: "(", count: 70) + String(repeating: ")", count: 70)] {
            XCTAssertThrowsError(try CPExpression.parse(text))
        }
    }
    func testQuotedCredentialsCannotInjectFields() throws {
        let value = "a\") :password (injected) \\ \""
        let encoded = CPWire.object("test", [("cookie", CPWire.quote(value))])
        let decoded = try CPExpression.parse(encoded)
        XCTAssertEqual(decoded.field("cookie")?.string, value)
        XCTAssertNil(decoded.field("password"))
    }
    func testSLIMFrameHasBigEndianLengthTypeAndControlTerminator() throws {
        XCTAssertEqual(try CPWire.frame(type: 2, payload: Data([1,2,3])), Data([0,0,0,3,0,0,0,2,1,2,3]))
        let control = try CPWire.control("(keepalive :id (0))")
        XCTAssertEqual(control.last, 0)
        XCTAssertEqual(control[7], 1)
        XCTAssertEqual(Int(control.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }), control.count - 8)
        XCTAssertThrowsError(try CPWire.frame(type: 9, payload: Data([1])))
        XCTAssertThrowsError(try CPWire.frame(type: 2, payload: Data(count: 1_000_001)))
    }
    func testRangeEdgesAndSentinel() throws {
        XCTAssertEqual(try IPv4Subnet.covering(from: "255.255.255.255", to: "255.255.255.255"), [.init(address: "255.255.255.255", mask: "255.255.255.255")])
        XCTAssertEqual(try IPv4Subnet.covering(from: "0.0.0.0", to: "255.255.255.255"), [.init(address: "0.0.0.0", mask: "0.0.0.0")])
        XCTAssertTrue(try IPv4Subnet.covering(from: "0.0.0.1", to: "255.255.255.255").isEmpty)
        XCTAssertThrowsError(try IPv4Subnet.covering(from: "10.0.0.9", to: "10.0.0.1"))
        XCTAssertNil(IPv4Subnet.number("10.0.0.256"))
    }
    func testProfileContainsNoPasswordAndValidatesEndpoint() throws {
        var profile = MobileProfile(); profile.host = "vpn.example.test"; try profile.validate()
        let encoded = try JSONEncoder().encode(profile)
        XCTAssertNil((try JSONSerialization.jsonObject(with: encoded) as? [String: Any])?["password"])
        profile.host = "https://vpn.example.test"; XCTAssertThrowsError(try profile.validate())
        profile.host = "vpn.example.test"; profile.port = "65536"; XCTAssertThrowsError(try profile.validate())
    }
    func testCertificateParserFailsClosed() {
        for data in [Data(), Data([0x30,0x80]), Data([0x30,0x82,0xff,0xff,0x00])] { XCTAssertThrowsError(try MobileCertificate(data: data)) }
    }
    func testCCCRejectsErrorOrEmptyResponse() throws {
        for text in ["(CCCserverResponse :ResponseHeader (:return_code (601)) :ResponseData (:error (failed)))", "(CCCserverResponse :ResponseHeader (:return_code (600)) :ResponseData ())"] {
            XCTAssertThrowsError(try MobileGateway.responseData(CPExpression.parse(text), request: "ClientHello"))
        }
    }
    func testCCCFormattingMatchesGatewayCompatibleClientHello() throws {
        let info = CPWire.fields([("client_type", "TRAC"), ("client_version", "1"), ("client_support_saml", "true")])
        let request = CPWire.ccc(type: "ClientHello", id: 1, data: CPWire.fields([("client_info", info)]))
        XCTAssertEqual(request, """
        (CCCclientRequest
        \t:RequestData (
        \t\t:client_info (
        \t\t\t:client_support_saml (true)
        \t\t\t:client_type (TRAC)
        \t\t\t:client_version (1)))
        \t:RequestHeader (
        \t\t:id (1)
        \t\t:type (ClientHello)))
        """)
    }
}
