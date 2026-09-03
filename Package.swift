// swift-tools-version: 6.4

import PackageDescription

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
            url: "https://github.com/swift-atoms/swift-standard-library-extensions.git",
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
                .product(name: "ASCII Serializer", package: "swift-ascii-serializer"),
                .product(name: "Binary Serializable", package: "swift-binary-serializer"),
                .product(name: "Parseable ASCII", package: "swift-ascii-parser"),
                .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions"),
                .product(name: "Binary", package: "swift-binary"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "Parser", package: "swift-parser"),
            ]
        ),
        .target(
            name: "RFC 7519 Standard Library Integration",
            dependencies: [
                .target(name: "RFC 7519"),
                .product(
                    name: "Byte Standard Library Integration",
                    package: "swift-byte"
                ),
            ]
        ),
        .testTarget(
            name: "RFC 7519 Tests",
            dependencies: [
                .target(name: "RFC 7519")
            ]
        ),
        .testTarget(
            name: "RFC 7519 Standard Library Integration Tests",
            dependencies: [
                .target(name: "RFC 7519"),
                .target(name: "RFC 7519 Standard Library Integration"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

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
