// swift-tools-version: 6.2

import PackageDescription

extension String {
    static let rfc7519: Self = "RFC 7519"
}

extension Target.Dependency {
    static var rfc7519: Self { .target(name: .rfc7519) }
    static var incits41986: Self { .product(name: "ASCII Serializer Primitives", package: "swift-ascii-serializer-primitives") }
    static var standards: Self { .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions") }
    static var binary: Self { .product(name: "Binary Primitives", package: "swift-binary-primitives") }
    static var rfc4648: Self { .product(name: "RFC 4648", package: "swift-rfc-4648") }
}

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26)
    ],
    products: [
        .library(name: "RFC 7519", targets: ["RFC 7519"]),
        .library(name: "RFC 7519 Standard Library Integration", targets: ["RFC 7519 Standard Library Integration"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-primitives/swift-ascii-serializer-primitives.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-standard-library-extensions.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-binary-primitives.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-byte-primitives.git", branch: "main"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4648.git", branch: "main"),
        .package(url: "https://github.com/swift-primitives/swift-parser-primitives.git", branch: "main")
    ],
    targets: [
        .target(
            name: "RFC 7519",
            dependencies: [
                .incits41986,
                .standards,
                .binary,
                .rfc4648,
                .product(name: "Parser Primitives", package: "swift-parser-primitives")
            ]
        ),
        .target(
            name: "RFC 7519 Standard Library Integration",
            dependencies: [
                "RFC 7519",
                .product(name: "Byte Primitives Standard Library Integration", package: "swift-byte-primitives"),
            ]
        ),
        .testTarget(
            name: "RFC 7519 Tests",
            dependencies: [
                "RFC 7519",
            ]
        ),
        .testTarget(
            name: "RFC 7519 Standard Library Integration Tests",
            dependencies: [
                "RFC 7519",
                "RFC 7519 Standard Library Integration",
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
}

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
