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

        let jwt = try RFC_7519.JWT(ascii: token.utf8)

        // Header should be decoded JSON bytes
        let headerString = String(decoding: jwt.header, as: UTF8.self)
        #expect(headerString.contains("HS256"))
        #expect(headerString.contains("JWT"))

        // Payload should be decoded JSON bytes
        let payloadString = String(decoding: jwt.payload, as: UTF8.self)
        #expect(payloadString.contains("1234567890"))
        #expect(payloadString.contains("John Doe"))

        // Signature should be non-empty
        #expect(!jwt.signature.isEmpty)
    }

    @Test
    func parseJWTWithEmptySignature() throws {
        // Unsecured JWT with empty signature
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."

        let jwt = try RFC_7519.JWT(ascii: token.utf8)

        let headerString = String(decoding: jwt.header, as: UTF8.self)
        #expect(headerString.contains("none"))

        #expect(jwt.signature.isEmpty)
    }

    @Test
    func parseJWTInvalidFormatTooFewParts() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "invalid.token".utf8)
        }
    }

    @Test
    func parseJWTInvalidFormatTooManyParts() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "too.many.parts.here".utf8)
        }
    }

    @Test
    func parseJWTEmpty() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "".utf8)
        }
    }

    @Test
    func parseJWTInvalidBase64URLInHeader() {
        // @ is not valid Base64URL
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "invalid@base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature".utf8)
        }
    }

    @Test
    func parseJWTInvalidBase64URLInPayload() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "eyJhbGciOiJIUzI1NiJ9.invalid@base64.signature".utf8)
        }
    }

    @Test
    func parseJWTInvalidBase64URLInSignature() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                ascii: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid@base64".utf8
            )
        }
    }

    @Test
    func parseJWTEmptyHeader() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: ".eyJzdWIiOiJ0ZXN0In0.sig".utf8)
        }
    }

    @Test
    func parseJWTEmptyPayload() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(ascii: "eyJhbGciOiJIUzI1NiJ9..sig".utf8)
        }
    }

    // MARK: - JWT Serialization Tests

    @Test
    func serializeJWT() throws {
        // Create a JWT from components
        let headerJSON = #"{"alg":"HS256","typ":"JWT"}"#
        let payloadJSON = #"{"sub":"test"}"#
        let signature: [UInt8] = [0x01, 0x02, 0x03, 0x04]

        let jwt = try RFC_7519.JWT(
            header: Array(headerJSON.utf8),
            payload: Array(payloadJSON.utf8),
            signature: signature
        )

        // Serialize to string
        let serialized = String(jwt)

        // Should have three parts separated by dots
        let parts = serialized.split(separator: ".")
        #expect(parts.count == 3)

        // Parse back and verify
        let parsed = try RFC_7519.JWT(ascii: serialized.utf8)
        #expect(parsed.header == jwt.header)
        #expect(parsed.payload == jwt.payload)
        #expect(parsed.signature == jwt.signature)
    }

    @Test
    func serializeToBytes() throws {
        let headerJSON = #"{"alg":"HS256"}"#
        let payloadJSON = #"{"sub":"user"}"#
        let signature: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]

        let jwt = try RFC_7519.JWT(
            header: Array(headerJSON.utf8),
            payload: Array(payloadJSON.utf8),
            signature: signature
        )

        // Serialize to bytes
        let bytes = [UInt8](jwt)
        #expect(!bytes.isEmpty)

        // Should be valid ASCII
        let string = String(decoding: bytes, as: UTF8.self)
        #expect(string.split(separator: ".").count == 3)
    }

    // MARK: - Round Trip Tests

    @Test
    func roundTripPreservesOriginalBase64URL() throws {
        let originalToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let jwt = try RFC_7519.JWT(ascii: originalToken.utf8)
        let serialized = String(jwt)

        // Should be exactly the same
        #expect(serialized == originalToken)
    }

    @Test
    func roundTripWithNewlyCreatedJWT() throws {
        let headerJSON = #"{"alg":"RS256","kid":"key1"}"#
        let payloadJSON = #"{"iss":"test","sub":"user123"}"#
        let signature: [UInt8] = Array(repeating: 0xAB, count: 32)

        let jwt = try RFC_7519.JWT(
            header: Array(headerJSON.utf8),
            payload: Array(payloadJSON.utf8),
            signature: signature
        )

        let serialized = String(jwt)
        let parsed = try RFC_7519.JWT(ascii: serialized.utf8)

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

        let jwt = try RFC_7519.JWT(ascii: originalToken.utf8)
        let signingInput = jwt.signingInput

        // Signing input should be header.payload (without signature)
        let signingInputString = String(decoding: signingInput, as: UTF8.self)
        #expect(
            signingInputString == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        )
    }

    @Test
    func signingInputPreservesOriginalEncoding() throws {
        // Valid JWT with proper Base64URL signature (c2lnbmF0dXJl is Base64URL for "signature")
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

        let jwt = try RFC_7519.JWT(ascii: token.utf8)
        let signingInput = jwt.signingInput
        let signingInputString = String(decoding: signingInput, as: UTF8.self)

        #expect(signingInputString == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
    }

    // MARK: - JWT Creation Tests

    @Test
    func createJWTFromComponents() throws {
        let header = Array(#"{"alg":"HS256"}"#.utf8)
        let payload = Array(#"{"sub":"123"}"#.utf8)
        let signature: [UInt8] = [0x01, 0x02, 0x03]

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
                header: [],
                payload: Array(#"{"sub":"test"}"#.utf8),
                signature: [0x01]
            )
        }
    }

    @Test
    func createJWTWithEmptyPayloadThrows() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                header: Array(#"{"alg":"HS256"}"#.utf8),
                payload: [],
                signature: [0x01]
            )
        }
    }

    @Test
    func createJWTWithEmptySignatureAllowed() throws {
        // Empty signature is allowed for unsecured JWTs (alg: none)
        let jwt = try RFC_7519.JWT(
            header: Array(#"{"alg":"none"}"#.utf8),
            payload: Array(#"{"sub":"test"}"#.utf8),
            signature: []
        )

        #expect(jwt.signature.isEmpty)
    }

    // MARK: - Equality Tests

    @Test
    func jwtEquality() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig123"

        let jwt1 = try RFC_7519.JWT(ascii: token.utf8)
        let jwt2 = try RFC_7519.JWT(ascii: token.utf8)

        #expect(jwt1 == jwt2)
    }

    @Test
    func jwtInequality() throws {
        let token1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MSJ9.sig1"
        let token2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MiJ9.sig2"

        let jwt1 = try RFC_7519.JWT(ascii: token1.utf8)
        let jwt2 = try RFC_7519.JWT(ascii: token2.utf8)

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

        let headerString = String(decoding: jwt.header, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }

    @Test
    func initFromSubstring() throws {
        let fullString = "prefix:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl:suffix"
        let token = fullString.dropFirst(7).dropLast(7)

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }
}
