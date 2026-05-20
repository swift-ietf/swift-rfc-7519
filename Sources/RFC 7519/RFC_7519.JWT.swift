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
        public let header: [Byte]

        /// The decoded payload bytes (JSON content)
        public let payload: [Byte]

        /// The decoded signature bytes
        public let signature: [Byte]

        /// Original Base64URL encoded header (for signing input preservation)
        package let headerBase64URL: [Byte]

        /// Original Base64URL encoded payload (for signing input preservation)
        package let payloadBase64URL: [Byte]

        /// Creates a JWT WITHOUT validation
        ///
        /// Private to ensure all public construction goes through validation.
        private init(
            __unchecked: Void,
            header: [Byte],
            payload: [Byte],
            signature: [Byte],
            headerBase64URL: [Byte],
            payloadBase64URL: [Byte]
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
            header: [Byte],
            payload: [Byte],
            signature: [Byte]
        ) throws(Error) {
            guard !header.isEmpty else {
                throw Error.emptyHeader
            }
            guard !payload.isEmpty else {
                throw Error.emptyPayload
            }
            // Signature can be empty for unsecured JWTs (alg: none)

            // Encode to Base64URL for signing input. RFC_4648 is still
            // UInt8-typed (deferred cohort); bridge via .underlying for input
            // and BSLI [Byte](source) for the encoded result.
            let headerBase64URL = [Byte](RFC_4648.Base64.URL.encode(header.underlying))
            let payloadBase64URL = [Byte](RFC_4648.Base64.URL.encode(payload.underlying))

            self.init(
                __unchecked: (),
                header: header,
                payload: payload,
                signature: signature,
                headerBase64URL: headerBase64URL,
                payloadBase64URL: payloadBase64URL
            )
        }

        // Stdlib-interop UInt8 forwarder lives in `RFC 7519 Standard Library
        // Integration` per [API-BYTE-007].
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
    public var signingInput: [Byte] {
        var result: [Byte] = []
        result.reserveCapacity(headerBase64URL.count + 1 + payloadBase64URL.count)
        result.append(contentsOf: headerBase64URL)
        // ASCII.Code.period bridges to a [Byte] sink via the BSLI
        // cross-byte-domain append.
        result.append(ASCII.Code.period)
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
    ) where Buffer.Element == Byte {
        // Storage is [Byte]; same-type append is exact.
        buffer.append(contentsOf: jwt.headerBase64URL)
        buffer.append(ASCII.Code.period)
        buffer.append(contentsOf: jwt.payloadBase64URL)
        buffer.append(ASCII.Code.period)
        // RFC_4648.Base64.URL.encode requires Bytes.Element == UInt8 and
        // Buffer.Element == UInt8 (deferred cohort); bridge jwt.signature via
        // .underlying for input, then append the UInt8 result via BSLI
        // cross-domain bridge.
        var signatureEncoded: [UInt8] = []
        RFC_4648.Base64.URL.encode(jwt.signature.underlying, into: &signatureEncoded, padding: false)
        buffer.append(contentsOf: signatureEncoded)
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
    /// - **Domain**: [Byte] (ASCII bytes - compact JWT format)
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
    where Bytes.Element == Byte {
        // Lift to ASCII.Code at the entry boundary: JWT compact form is strict
        // ASCII (Base64URL alphabet + period); non-ASCII bytes are fail-state.
        let arr = Array<ASCII.Code>(bytes)
        guard !arr.isEmpty else { throw Error.empty }

        // Find the two period separators
        var firstPeriodIndex: Int?
        var secondPeriodIndex: Int?

        for (index, code) in arr.enumerated() {
            if code == ASCII.Code.period {
                if firstPeriodIndex == nil {
                    firstPeriodIndex = index
                } else if secondPeriodIndex == nil {
                    secondPeriodIndex = index
                } else {
                    // More than two periods
                    throw Error.invalidFormat(String(decoding: arr, as: UTF8.self))
                }
            }
        }

        guard let first = firstPeriodIndex, let second = secondPeriodIndex else {
            throw Error.invalidFormat(String(decoding: arr, as: UTF8.self))
        }

        // Extract the three parts as staging [UInt8] for the RFC_4648 hand-off
        // (deferred cohort, still UInt8-typed). Storage is [Byte]; wrap via
        // BSLI [Byte](source) before passing to __unchecked init.
        let headerBase64URL_u8 = Array<UInt8>(arr[..<first])
        let payloadBase64URL_u8 = Array<UInt8>(arr[(first + 1)..<second])
        let signatureBase64URL_u8 = Array<UInt8>(arr[(second + 1)...])

        // Decode header
        guard !headerBase64URL_u8.isEmpty else {
            throw Error.emptyHeader
        }
        guard let header_u8 = RFC_4648.Base64.URL.decode(headerBase64URL_u8) else {
            throw Error.invalidBase64URL(
                String(decoding: headerBase64URL_u8, as: UTF8.self),
                component: "header"
            )
        }

        // Decode payload
        guard !payloadBase64URL_u8.isEmpty else {
            throw Error.emptyPayload
        }
        guard let payload_u8 = RFC_4648.Base64.URL.decode(payloadBase64URL_u8) else {
            throw Error.invalidBase64URL(
                String(decoding: payloadBase64URL_u8, as: UTF8.self),
                component: "payload"
            )
        }

        // Decode signature (can be empty for unsecured JWTs)
        let signature_u8: [UInt8]
        if signatureBase64URL_u8.isEmpty {
            signature_u8 = []
        } else {
            guard let decoded = RFC_4648.Base64.URL.decode(signatureBase64URL_u8) else {
                throw Error.invalidBase64URL(
                    String(decoding: signatureBase64URL_u8, as: UTF8.self),
                    component: "signature"
                )
            }
            signature_u8 = decoded
        }

        self.init(
            __unchecked: (),
            header: [Byte](header_u8),
            payload: [Byte](payload_u8),
            signature: [Byte](signature_u8),
            headerBase64URL: [Byte](headerBase64URL_u8),
            payloadBase64URL: [Byte](payloadBase64URL_u8)
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
