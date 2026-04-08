// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7519 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

public import ASCII_Serializer_Primitives

extension RFC_7519 {
    /// A JSON Web Token as defined in RFC 7519
    ///
    /// A JWT represents claims securely between two parties. It consists of three
    /// Base64URL-encoded parts separated by dots: header.payload.signature
    ///
    /// ## ABNF Grammar (RFC 7519 / RFC 7515)
    ///
    /// ```
    /// JWT = BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
    /// ```
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Parse a JWT
    /// let jwt = try RFC_7519.JWT(ascii: tokenString.utf8)
    ///
    /// // Access the raw parts
    /// print(jwt.header)     // Base64URL-decoded header bytes
    /// print(jwt.payload)    // Base64URL-decoded payload bytes
    /// print(jwt.signature)  // Base64URL-decoded signature bytes
    /// ```
    ///
    /// ## Note
    ///
    /// This type provides structural parsing of JWTs. The header and payload
    /// contain JSON data that should be parsed separately using a JSON parser.
    /// This design keeps the RFC implementation Foundation-free.
    public struct JWT: Sendable, Codable {
        /// The decoded header bytes (JSON content)
        public let header: [UInt8]

        /// The decoded payload bytes (JSON content)
        public let payload: [UInt8]

        /// The decoded signature bytes
        public let signature: [UInt8]

        /// Original Base64URL encoded header (for signing input preservation)
        package let headerBase64URL: [UInt8]

        /// Original Base64URL encoded payload (for signing input preservation)
        package let payloadBase64URL: [UInt8]

        /// Creates a JWT WITHOUT validation
        ///
        /// Private to ensure all public construction goes through validation.
        private init(
            __unchecked: Void,
            header: [UInt8],
            payload: [UInt8],
            signature: [UInt8],
            headerBase64URL: [UInt8],
            payloadBase64URL: [UInt8]
        ) {
            self.header = header
            self.payload = payload
            self.signature = signature
            self.headerBase64URL = headerBase64URL
            self.payloadBase64URL = payloadBase64URL
        }

        /// Creates a JWT from decoded components
        ///
        /// - Parameters:
        ///   - header: The decoded header bytes (JSON)
        ///   - payload: The decoded payload bytes (JSON)
        ///   - signature: The decoded signature bytes
        /// - Throws: `Error` if components are invalid
        public init(
            header: [UInt8],
            payload: [UInt8],
            signature: [UInt8]
        ) throws(Error) {
            guard !header.isEmpty else {
                throw Error.emptyHeader
            }
            guard !payload.isEmpty else {
                throw Error.emptyPayload
            }
            // Signature can be empty for unsecured JWTs (alg: none)

            // Encode to Base64URL for signing input
            let headerBase64URL = RFC_4648.Base64.URL.encode(header)
            let payloadBase64URL = RFC_4648.Base64.URL.encode(payload)

            self.init(
                __unchecked: (),
                header: header,
                payload: payload,
                signature: signature,
                headerBase64URL: headerBase64URL,
                payloadBase64URL: payloadBase64URL
            )
        }
    }
}

// MARK: - Signing Input

extension RFC_7519.JWT {
    /// The signing input for this JWT
    ///
    /// Per RFC 7515, the signing input is `BASE64URL(header).BASE64URL(payload)`
    /// encoded as ASCII bytes. This is what gets signed/verified.
    ///
    /// - Returns: The signing input bytes
    public var signingInput: [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(headerBase64URL.count + 1 + payloadBase64URL.count)
        result.append(contentsOf: headerBase64URL)
        result.append(UInt8.ascii.period)
        result.append(contentsOf: payloadBase64URL)
        return result
    }
}

// MARK: - Binary.ASCII.Serializable

extension RFC_7519.JWT: Binary.ASCII.Serializable {
    /// Serialize JWT to compact format (header.payload.signature)
    ///
    /// Per RFC 7519/7515, outputs Base64URL-encoded parts separated by periods.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        ascii jwt: RFC_7519.JWT,
        into buffer: inout Buffer
    ) where Buffer.Element == UInt8 {
        // Use stored Base64URL-encoded values for header and payload
        buffer.append(contentsOf: jwt.headerBase64URL)
        buffer.append(UInt8.ascii.period)
        buffer.append(contentsOf: jwt.payloadBase64URL)
        buffer.append(UInt8.ascii.period)
        RFC_4648.Base64.URL.encode(jwt.signature, into: &buffer, padding: false)
    }

    /// Parses a JWT from its compact serialization format (AUTHORITATIVE IMPLEMENTATION)
    ///
    /// ## RFC 7519 / RFC 7515 Format
    ///
    /// ```
    /// BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
    /// ```
    ///
    /// ## Category Theory
    ///
    /// Parsing transformation:
    /// - **Domain**: [UInt8] (ASCII bytes - compact JWT format)
    /// - **Codomain**: RFC_7519.JWT (structured data)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let jwt = try RFC_7519.JWT(ascii: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig".utf8)
    /// ```
    ///
    /// - Parameter bytes: The JWT as ASCII bytes in compact format
    /// - Throws: `Error` if parsing fails
    public init<Bytes: Collection>(ascii bytes: Bytes, in context: Void = ()) throws(Error)
    where Bytes.Element == UInt8 {
        let byteArray = Array(bytes)
        guard !byteArray.isEmpty else { throw Error.empty }

        // Find the two period separators
        var firstPeriodIndex: Int?
        var secondPeriodIndex: Int?

        for (index, byte) in byteArray.enumerated() {
            if byte == UInt8.ascii.period {
                if firstPeriodIndex == nil {
                    firstPeriodIndex = index
                } else if secondPeriodIndex == nil {
                    secondPeriodIndex = index
                } else {
                    // More than two periods
                    throw Error.invalidFormat(String(decoding: byteArray, as: UTF8.self))
                }
            }
        }

        guard let first = firstPeriodIndex, let second = secondPeriodIndex else {
            throw Error.invalidFormat(String(decoding: byteArray, as: UTF8.self))
        }

        // Extract the three parts
        let headerBase64URL = Array(byteArray[..<first])
        let payloadBase64URL = Array(byteArray[(first + 1)..<second])
        let signatureBase64URL = Array(byteArray[(second + 1)...])

        // Decode header
        guard !headerBase64URL.isEmpty else {
            throw Error.emptyHeader
        }
        guard let header = RFC_4648.Base64.URL.decode(headerBase64URL) else {
            throw Error.invalidBase64URL(
                String(decoding: headerBase64URL, as: UTF8.self),
                component: "header"
            )
        }

        // Decode payload
        guard !payloadBase64URL.isEmpty else {
            throw Error.emptyPayload
        }
        guard let payload = RFC_4648.Base64.URL.decode(payloadBase64URL) else {
            throw Error.invalidBase64URL(
                String(decoding: payloadBase64URL, as: UTF8.self),
                component: "payload"
            )
        }

        // Decode signature (can be empty for unsecured JWTs)
        let signature: [UInt8]
        if signatureBase64URL.isEmpty {
            signature = []
        } else {
            guard let decoded = RFC_4648.Base64.URL.decode(signatureBase64URL) else {
                throw Error.invalidBase64URL(
                    String(decoding: signatureBase64URL, as: UTF8.self),
                    component: "signature"
                )
            }
            signature = decoded
        }

        self.init(
            __unchecked: (),
            header: header,
            payload: payload,
            signature: signature,
            headerBase64URL: headerBase64URL,
            payloadBase64URL: payloadBase64URL
        )
    }
}

// MARK: - Protocol Conformances

extension RFC_7519.JWT: Binary.ASCII.RawRepresentable {
    public typealias RawValue = String
}

extension RFC_7519.JWT: CustomStringConvertible {}

extension RFC_7519.JWT: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(header)
        hasher.combine(payload)
        hasher.combine(signature)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.header == rhs.header
            && lhs.payload == rhs.payload
            && lhs.signature == rhs.signature
    }
}
