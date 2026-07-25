# Swift RFC 7519

![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)
[![CI](https://github.com/swift-ietf/swift-rfc-7519/workflows/CI/badge.svg)](https://github.com/swift-ietf/swift-rfc-7519/actions/workflows/ci.yml)

Swift implementation of RFC 7519: JSON Web Token (JWT).

## Overview

RFC 7519 defines JSON Web Token (JWT), a compact, URL-safe means of representing claims to be transferred between two parties. This package provides a pure Swift implementation of JWT parsing, validation, and serialization without cryptographic dependencies, making it lightweight and universally compatible across all Swift platforms. The crypto-agnostic design allows you to choose your own signature implementation or use JWT inspection without verification.

## Features

- **RFC Compliant**: Full implementation of RFC 7519 JWT specification
- **Zero Crypto Dependencies**: Pure Swift JWT handling with optional crypto integration
- **Complete Claims Support**: All registered claims (iss, sub, aud, exp, nbf, iat, jti) plus custom claims
- **Timing Validation**: Built-in expiration and not-before validation with clock skew tolerance
- **Base64URL**: Proper RFC 4648 base64url encoding/decoding
- **Type-Safe**: Strongly typed claims with generic access methods
- **Sendable**: Full Swift 6 concurrency support
- **Cross-Platform**: Works on all Swift platforms

## Installation

Add swift-rfc-7519 to your package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-7519.git", from: "0.1.5")
]
```

Then add it to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 7519", package: "swift-rfc-7519")
    ]
)
```

## Quick Start

### Parsing and Inspecting JWTs

```swift
import RFC_7519

// Parse a JWT token
let tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlLmNvbSIsInN1YiI6InVzZXIxMjMiLCJleHAiOjE3MzAwMDAwMDB9.signature"
let jwt = try RFC_7519.JWT.parse(from: tokenString)

// Access standard claims
print("Issuer: \(jwt.payload.iss ?? "unknown")")
print("Subject: \(jwt.payload.sub ?? "unknown")")
print("Expires: \(jwt.payload.exp ?? 0)")

// Access custom claims
if let role = jwt.payload.additionalClaim("role", as: String.self) {
    print("Role: \(role)")
}

// Check header information
print("Algorithm: \(jwt.header.alg)")
print("Type: \(jwt.header.typ ?? "JWT")")
```

### Validating JWT Timing

```swift
// Validate expiration and not-before claims
try jwt.payload.validateTiming()

// Validate with custom clock skew tolerance (default is 60 seconds)
try jwt.payload.validateTiming(clockSkew: 120)

// Manual expiration check
if let exp = jwt.payload.exp, Date(timeIntervalSince1970: exp) < Date() {
    print("Token has expired")
}
```

### Creating JWTs

```swift
// Create JWT payload
let payload = RFC_7519.JWT.Payload(
    iss: "example.com",
    sub: "user123",
    aud: .single("https://api.example.com"),
    exp: Date().addingTimeInterval(3600),
    iat: Date(),
    additionalClaims: ["role": "admin", "department": "engineering"]
)

// Create JWT header
let header = RFC_7519.JWT.Header(
    alg: "HS256",
    typ: "JWT"
)

// Create JWT (requires signature - see below for signing)
let signature = Data() // Replace with actual signature
let jwt = RFC_7519.JWT(header: header, payload: payload, signature: signature)

// Serialize to string
let tokenString = try jwt.compactSerialization()
```

### Working with Audiences

```swift
// Single audience
let payload1 = RFC_7519.JWT.Payload(
    iss: "example.com",
    sub: "user123",
    aud: .single("https://api.example.com")
)

// Multiple audiences
let payload2 = RFC_7519.JWT.Payload(
    iss: "example.com",
    sub: "user123",
    aud: .multiple(["https://api.example.com", "https://admin.example.com"])
)

// Access audience values
if case .single(let aud) = payload1.aud {
    print("Single audience: \(aud)")
}

if case .multiple(let auds) = payload2.aud {
    print("Multiple audiences: \(auds)")
}
```

## Usage

### JWT Structure

```swift
public struct JWT: Codable, Hashable, Sendable {
    public let header: Header
    public let payload: Payload
    public let signature: Data

    init(header: Header, payload: Payload, signature: Data)
    static func parse(from token: String) throws -> JWT
    func compactSerialization() throws -> String
    func signingInput() throws -> Data
}
```

### Header

```swift
public struct Header: Codable, Hashable, Sendable {
    public let alg: String      // Algorithm (required)
    public let typ: String?     // Type (typically "JWT")
    public let cty: String?     // Content type
    public let kid: String?     // Key ID

    func additionalParameter<T>(_ key: String, as type: T.Type) -> T?
}
```

### Payload (Claims)

```swift
public struct Payload: Codable, Hashable, Sendable {
    public let iss: String?                         // Issuer
    public let sub: String?                         // Subject
    public let aud: Audience?                       // Audience
    public let exp: Date?                           // Expiration time
    public let nbf: Date?                           // Not before time
    public let iat: Date?                           // Issued at time
    public let jti: String?                         // JWT ID

    func additionalClaim<T>(_ key: String, as type: T.Type) -> T?
    func validateTiming(clockSkew: TimeInterval = 60) throws
}
```

### Audience Type

```swift
public enum Audience: Codable, Hashable, Sendable {
    case single(String)
    case multiple([String])
}
```

### Error Types

```swift
public enum Error: Swift.Error {
    case invalidFormat(String)
    case invalidSignature
    case tokenExpired
    case tokenNotYetValid
}
```

## Related Packages

### Dependencies
- None - This is a pure Swift implementation

### Recommended Crypto Libraries
- [CryptoKit](https://developer.apple.com/documentation/cryptokit) - Apple's cryptography framework (Apple platforms)
- [Swift Crypto](https://github.com/apple/swift-crypto) - Cross-platform Swift cryptography

### Related Standards
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html) - JSON Web Signature (JWS)
- [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) - JSON Web Encryption (JWE)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) - JSON Web Key (JWK)
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) - JSON Web Algorithms (JWA)

## Requirements

- Swift 6.0+
- macOS 13.0+ / iOS 16.0+ / tvOS 16.0+ / watchOS 9.0+

## License

This library is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
