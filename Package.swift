// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "swift-rfc-7519",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
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
            url: "https://github.com/swift-atoms/swift-standard-library-extensions.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-binary.git",
            branch: "main", traits: ["Serializer"]),
        .package(
            url: "https://github.com/swift-atoms/swift-byte.git",
            branch: "main"
        ),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4648.git", branch: "main"),
        .package(
            url: "https://github.com/swift-atoms/swift-parser.git",
            branch: "main", traits: ["Append", "IteratorLeaves", "Map", "Product", "Skip", "Either", "Iterator", "Collection"]
        ),
        .package(url: "https://github.com/swift-atoms/swift-ascii.git", branch: "main", traits: ["Parser", "Serializer"]),
    ],
    targets: [
        .target(
            name: "RFC 7519",
            dependencies: [
                .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions"),
                .product(name: "Binary", package: "swift-binary"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "Parser", package: "swift-parser"),
                .product(name: "ASCII", package: "swift-ascii"),
            ]
        ),
        .target(
            name: "RFC 7519 Standard Library Integration",
            dependencies: [
                .target(name: "RFC 7519"),
                .product(
                    name: "Byte",
                    package: "swift-byte"
                ),
            ]
        ),
        .testTarget(
            name: "RFC 7519 Tests",
            dependencies: [
                .target(name: "RFC 7519"),
                .product(name: "Binary", package: "swift-binary"),
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
