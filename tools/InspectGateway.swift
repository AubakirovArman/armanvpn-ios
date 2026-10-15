import Foundation

// Read-only preflight. Does not authenticate or create a VPN session.
@main struct InspectGateway {
    static func main() async {
        do {
            guard let input = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as? [String: String],
                  let host = input["host"], let approved = input["fingerprint"] else { throw MobileVPNError.message("Pass host and an explicitly approved SHA-256 fingerprint on stdin.") }
            var profile = MobileProfile(); profile.host = host; profile.port = input["port"] ?? "443"
            let certificate = try await MobileGateway.inspect(profile)
            guard certificate.fingerprint == approved, certificate.isCurrent else { throw MobileVPNError.message("Certificate differs from the explicitly approved fingerprint, or is expired.") }
            let gateway = MobileGateway(profile: profile, certificate: certificate.data)
            let info = try await gateway.information()
            let stream = try TLSChannel(host: profile.host, port: info.tunnelPort, certificate: certificate.data)
            try await stream.open(); stream.cancel()
            print("Certificate: \(certificate.subject)")
            print("Valid until: \(ISO8601DateFormatter().string(from: certificate.expires))")
            print("Pinned TLS: passed")
            print("CCC ClientHello: passed; login options: \(info.options.count); SSL port: \(info.tunnelPort)")
        } catch { print(error.localizedDescription); exit(1) }
    }
}
