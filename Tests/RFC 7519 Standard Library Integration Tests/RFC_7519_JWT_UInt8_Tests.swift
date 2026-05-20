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
import RFC_7519
import RFC_7519_Standard_Library_Integration

@Suite("RFC 7519 JWT UInt8 forwarder")
struct RFC_7519_JWT_UInt8_Tests {
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
}
