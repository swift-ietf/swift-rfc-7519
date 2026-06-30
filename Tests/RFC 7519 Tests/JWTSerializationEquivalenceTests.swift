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
//
// [FAM-012] composite re-cut guard. The JWT `ASCII.Serializable` verb (emitting
// onto the ASCII-code substrate) MUST emit byte-identical output to the
// `Binary.Serializable` witness (`serializeBytes`) for the Base64URL ENCODE path
// — the URL-safe alphabet ('-' / '_') being the algorithm re-expressed per
// substrate. Asserts the refactor invariant directly (ASCII output == Binary
// output), so no expected string is hand-derived.
//

import Testing
import Binary_Serializable_Primitives

@testable import RFC_7519

@Suite
struct JWTSerializationEquivalenceTests {

    @Test
    func asciiVerbOutputEqualsBinaryWitnessOutputForTheBase64URLEncodePath() throws {
        // Segment bytes chosen so every part's Base64URL encoding exercises the
        // URL-safe alphabet ('-' = sextet 62, '_' = sextet 63) and the unpadded
        // tail (RFC 7515: padding: false). header [0xFF,0xFF,0xBF] -> "__-_",
        // payload [0xFB,0xF0] -> "-_A", signature [0xFF,0xEF,0xFB] -> "_-_7".
        let jwt = try RFC_7519.JWT(
            header: [0xFF, 0xFF, 0xBF],
            payload: [0xFB, 0xF0],
            signature: [0xFF, 0xEF, 0xFB]
        )

        // ASCII.Serializable verb output, projected to bytes.
        let viaASCII: [Byte] = jwt.serialized

        // Binary.Serializable witness output.
        var viaBinary: [Byte] = []
        RFC_7519.JWT.serialize(jwt, into: &viaBinary)

        #expect(viaASCII == viaBinary)

        // Confirm the chosen inputs actually drive the URL-safe alphabet, so the
        // equivalence above is meaningful for the '-' / '_' encode branches.
        let text = String(decoding: viaASCII.underlying, as: UTF8.self)
        #expect(text.contains("-"))
        #expect(text.contains("_"))
    }
}
