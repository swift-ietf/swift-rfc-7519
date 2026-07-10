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

import RFC_7519
import RFC_7519_Standard_Library_Integration
import Testing

extension RFC_7519.JWT {
    @Suite("RFC 7519 JWT UInt8 forwarder")
    struct Test {
        @Test
        func `create JWT Via UInt8 Forwarder`() throws {
            // Callers holding stdlib [UInt8] (network frames, base64 decoders) reach
            // the @_disfavoredOverload UInt8 forwarder without manual bridging.
            let headerU8: [UInt8] = Array(#"{"alg":"HS256"}"#.utf8)
            let payloadU8: [UInt8] = Array(#"{"sub":"test"}"#.utf8)
            let signatureU8: [UInt8] = [0x01, 0x02, 0x03]

            let jwt = try RFC_7519.JWT(
                header: headerU8,
                payload: payloadU8,
                signature: signatureU8
            )

            // Storage retains the Byte-typed identity post-bridging.
            #expect(jwt.header == [Byte](headerU8))
            #expect(jwt.payload == [Byte](payloadU8))
            #expect(jwt.signature == [Byte](signatureU8))
        }
    }
}
