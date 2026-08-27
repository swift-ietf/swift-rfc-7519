// swift-tools-version: 6.4

import PackageDescription

extension String {
    static let rfc7519: Self = "RFC 7519"
}

extension Target.Dependency {
    static var rfc7519: Self { .target(name: .rfc7519) }
    static var incits41986: Self {
        .product(name: "ASCII Serializer", package: "swift-ascii-serializer")
    }
    static var standards: Self {
        .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions")
    }
    static var binary: Self {
        .product(name: "Binary", package: "swift-binary")
    }
    static var binarySerializable: Self {
        .product(
            name: "Binary Serializable",
            package: "swift-binary-serializer"
        )
    }
    static var parseableASCII: Self {
        .product(name: "Parseable ASCII", package: "swift-ascii-parser")
    }
    static var rfc4648: Self { .product(name: "RFC 4648", package: "swift-rfc-4648") }
}

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
    ],
    products: [
        .library(name: "RFC 7519", targets: ["RFC 7519"]),
        .library(
            name: "RFC 7519 Standard Library Integration",
            targets: ["RFC 7519 Standard Library Integration"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-molecules/swift-ascii-serializer.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-binary-serializer.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-ascii-parser.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-standard-library-extensions.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-binary.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-byte.git",
            branch: "main"
        ),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4648.git", branch: "main"),
        .package(
            url: "https://github.com/swift-molecules/swift-parser.git",
            branch: "main"
        ),
    ],
    targets: [
        .target(
            name: "RFC 7519",
            dependencies: [
                .incits41986,
                .binarySerializable,
                .parseableASCII,
                .standards,
                .binary,
                .rfc4648,
                .product(name: "Parser", package: "swift-parser"),
            ]
        ),
        .target(
            name: "RFC 7519 Standard Library Integration",
            dependencies: [
                "RFC 7519",
                .product(
                    name: "Byte Standard Library Integration",
                    package: "swift-byte"
                ),
            ]
        ),
        .testTarget(
            name: "RFC 7519 Tests",
            dependencies: [
                "RFC 7519"
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
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
