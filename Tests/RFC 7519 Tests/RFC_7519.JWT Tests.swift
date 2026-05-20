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

import Testing

@testable import RFC_7519

@Suite
struct JWTTests {

    // MARK: - JWT Parsing Tests

    @Test
    func parseValidJWT() throws {
        // Example JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}.signature
        let token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let jwt = try RFC_7519.JWT(token)

        // Header should be decoded JSON bytes
        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
        #expect(headerString.contains("JWT"))

        // Payload should be decoded JSON bytes
        let payloadString = String(decoding: jwt.payload.underlying, as: UTF8.self)
        #expect(payloadString.contains("1234567890"))
        #expect(payloadString.contains("John Doe"))

        // Signature should be non-empty
        #expect(!jwt.signature.isEmpty)
    }

    @Test
    func parseJWTWithEmptySignature() throws {
        // Unsecured JWT with empty signature
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("none"))

        #expect(jwt.signature.isEmpty)
    }

    @Test
    func parseJWTInvalidFormatTooFewParts() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("invalid.token")
        }
    }

    @Test
    func parseJWTInvalidFormatTooManyParts() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("too.many.parts.here")
        }
    }

    @Test
    func parseJWTEmpty() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("")
        }
    }

    @Test
    func parseJWTInvalidBase64URLInHeader() {
        // @ is not valid Base64URL
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("invalid@base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
        }
    }

    @Test
    func parseJWTInvalidBase64URLInPayload() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("eyJhbGciOiJIUzI1NiJ9.invalid@base64.signature")
        }
    }

    @Test
    func parseJWTInvalidBase64URLInSignature() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid@base64"
            )
        }
    }

    @Test
    func parseJWTEmptyHeader() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(".eyJzdWIiOiJ0ZXN0In0.sig")
        }
    }

    @Test
    func parseJWTEmptyPayload() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("eyJhbGciOiJIUzI1NiJ9..sig")
        }
    }

    // MARK: - JWT Serialization Tests

    @Test
    func serializeJWT() throws {
        // Create a JWT from components
        let headerJSON = #"{"alg":"HS256","typ":"JWT"}"#
        let payloadJSON = #"{"sub":"test"}"#
        let signature: [Byte] = [0x01, 0x02, 0x03, 0x04]

        let jwt = try RFC_7519.JWT(
            header: [Byte](headerJSON.utf8),
            payload: [Byte](payloadJSON.utf8),
            signature: signature
        )

        // Serialize to string
        let serialized = String(jwt)

        // Should have three parts separated by dots
        let parts = serialized.split(separator: ".")
        #expect(parts.count == 3)

        // Parse back and verify
        let parsed = try RFC_7519.JWT(serialized)
        #expect(parsed.header == jwt.header)
        #expect(parsed.payload == jwt.payload)
        #expect(parsed.signature == jwt.signature)
    }

    @Test
    func serializeToBytes() throws {
        let headerJSON = #"{"alg":"HS256"}"#
        let payloadJSON = #"{"sub":"user"}"#
        let signature: [Byte] = [0xDE, 0xAD, 0xBE, 0xEF]

        let jwt = try RFC_7519.JWT(
            header: [Byte](headerJSON.utf8),
            payload: [Byte](payloadJSON.utf8),
            signature: signature
        )

        // Serialize to bytes (Binary.Serializable [Byte] result + stdlib-interop
        // [UInt8] forwarder both available; this site uses the [Byte] primary).
        let bytes: [Byte] = Array(jwt)
        #expect(!bytes.isEmpty)

        // Should be valid ASCII
        let string = String(decoding: bytes.underlying, as: UTF8.self)
        #expect(string.split(separator: ".").count == 3)
    }

    // MARK: - Round Trip Tests

    @Test
    func roundTripPreservesOriginalBase64URL() throws {
        let originalToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let jwt = try RFC_7519.JWT(originalToken)
        let serialized = String(jwt)

        // Should be exactly the same
        #expect(serialized == originalToken)
    }

    @Test
    func roundTripWithNewlyCreatedJWT() throws {
        let headerJSON = #"{"alg":"RS256","kid":"key1"}"#
        let payloadJSON = #"{"iss":"test","sub":"user123"}"#
        let signature: [Byte] = Array(repeating: 0xAB, count: 32)

        let jwt = try RFC_7519.JWT(
            header: [Byte](headerJSON.utf8),
            payload: [Byte](payloadJSON.utf8),
            signature: signature
        )

        let serialized = String(jwt)
        let parsed = try RFC_7519.JWT(serialized)

        #expect(parsed.header == jwt.header)
        #expect(parsed.payload == jwt.payload)
        #expect(parsed.signature == jwt.signature)
    }

    // MARK: - Signing Input Tests

    @Test
    func signingInputIsCorrect() throws {
        // Valid JWT with proper Base64URL signature
        let originalToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        let jwt = try RFC_7519.JWT(originalToken)
        let signingInput = jwt.signingInput

        // Signing input should be header.payload (without signature)
        let signingInputString = String(decoding: signingInput.underlying, as: UTF8.self)
        #expect(
            signingInputString == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        )
    }

    @Test
    func signingInputPreservesOriginalEncoding() throws {
        // Valid JWT with proper Base64URL signature (c2lnbmF0dXJl is Base64URL for "signature")
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

        let jwt = try RFC_7519.JWT(token)
        let signingInput = jwt.signingInput
        let signingInputString = String(decoding: signingInput.underlying, as: UTF8.self)

        #expect(signingInputString == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
    }

    // MARK: - JWT Creation Tests

    @Test
    func createJWTFromComponents() throws {
        let header: [Byte] = [Byte](#"{"alg":"HS256"}"#.utf8)
        let payload: [Byte] = [Byte](#"{"sub":"123"}"#.utf8)
        let signature: [Byte] = [0x01, 0x02, 0x03]

        let jwt = try RFC_7519.JWT(
            header: header,
            payload: payload,
            signature: signature
        )

        #expect(jwt.header == header)
        #expect(jwt.payload == payload)
        #expect(jwt.signature == signature)
    }

    @Test
    func createJWTWithEmptyHeaderThrows() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                header: [Byte](),
                payload: [Byte](#"{"sub":"test"}"#.utf8),
                signature: [0x01]
            )
        }
    }

    @Test
    func createJWTWithEmptyPayloadThrows() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                header: [Byte](#"{"alg":"HS256"}"#.utf8),
                payload: [Byte](),
                signature: [0x01]
            )
        }
    }

    @Test
    func createJWTWithEmptySignatureAllowed() throws {
        // Empty signature is allowed for unsecured JWTs (alg: none)
        let jwt = try RFC_7519.JWT(
            header: [Byte](#"{"alg":"none"}"#.utf8),
            payload: [Byte](#"{"sub":"test"}"#.utf8),
            signature: []
        )

        #expect(jwt.signature.isEmpty)
    }

    // MARK: - Stdlib-interop forwarder ([UInt8] -> [Byte] @_disfavoredOverload)

    @Test
    func createJWTViaUInt8Forwarder() throws {
        // Callers holding stdlib [UInt8] (network frames, base64 decoders) reach
        // the @_disfavoredOverload UInt8 forwarder without manual bridging.
        let header_u8: [UInt8] = Array(#"{"alg":"HS256"}"#.utf8)
        let payload_u8: [UInt8] = Array(#"{"sub":"test"}"#.utf8)
        let signature_u8: [UInt8] = [0x01, 0x02, 0x03]

        let jwt = try RFC_7519.JWT(
            header: header_u8,
            payload: payload_u8,
            signature: signature_u8
        )

        // Storage retains the Byte-typed identity post-bridging.
        #expect(jwt.header == [Byte](header_u8))
        #expect(jwt.payload == [Byte](payload_u8))
        #expect(jwt.signature == [Byte](signature_u8))
    }

    // MARK: - Equality Tests

    @Test
    func jwtEquality() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig123"

        let jwt1 = try RFC_7519.JWT(token)
        let jwt2 = try RFC_7519.JWT(token)

        #expect(jwt1 == jwt2)
    }

    @Test
    func jwtInequality() throws {
        let token1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MSJ9.sig1"
        let token2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MiJ9.sig2"

        let jwt1 = try RFC_7519.JWT(token1)
        let jwt2 = try RFC_7519.JWT(token2)

        #expect(jwt1 != jwt2)
    }

    // MARK: - Error Description Tests

    @Test
    func errorDescriptions() {
        let emptyError = RFC_7519.JWT.Error.empty
        #expect(emptyError.description.contains("empty"))

        let emptyHeaderError = RFC_7519.JWT.Error.emptyHeader
        #expect(emptyHeaderError.description.contains("header"))

        let emptyPayloadError = RFC_7519.JWT.Error.emptyPayload
        #expect(emptyPayloadError.description.contains("payload"))

        let formatError = RFC_7519.JWT.Error.invalidFormat("test")
        #expect(formatError.description.contains("format"))

        let base64Error = RFC_7519.JWT.Error.invalidBase64URL("abc", component: "header")
        #expect(base64Error.description.contains("Base64URL"))
        #expect(base64Error.description.contains("header"))
    }

    // MARK: - StringProtocol Init Tests

    @Test
    func initFromString() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }

    @Test
    func initFromSubstring() throws {
        let fullString = "prefix:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl:suffix"
        let token = fullString.dropFirst(7).dropLast(7)

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }
}
