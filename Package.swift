// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ArmanVPNMobileCore",
    platforms: [.macOS(.v14), .iOS(.v17)],
    targets: [
        .target(name: "ArmanVPNMobileCore", path: "Shared"),
        .testTarget(name: "ArmanVPNMobileCoreTests", dependencies: ["ArmanVPNMobileCore"], path: "Tests", resources: [.copy("Fixtures")])
    ],
    swiftLanguageModes: [.v5]
)
