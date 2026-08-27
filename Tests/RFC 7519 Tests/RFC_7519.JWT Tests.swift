import Binary_Serializable
import Testing

@testable import RFC_7519

extension RFC_7519.JWT.Test {

    @Test
    func `parse Valid JWT`() throws {

        let token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
        #expect(headerString.contains("JWT"))

        let payloadString = String(decoding: jwt.payload.underlying, as: UTF8.self)
        #expect(payloadString.contains("1234567890"))
        #expect(payloadString.contains("John Doe"))

        #expect(!jwt.signature.isEmpty)
    }

    @Test
    func `parse JWT With Empty Signature`() throws {

        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("none"))

        #expect(jwt.signature.isEmpty)
    }

    @Test
    func `parse JWT Invalid Format Too Few Parts`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("invalid.token")
        }
    }

    @Test
    func `parse JWT Invalid Format Too Many Parts`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("too.many.parts.here")
        }
    }

    @Test
    func `parse JWT Empty`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("")
        }
    }

    @Test
    func `parse JWT Invalid Base64URL In Header`() {

        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("invalid@base64.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
        }
    }

    @Test
    func `parse JWT Invalid Base64URL In Payload`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("eyJhbGciOiJIUzI1NiJ9.invalid@base64.signature")
        }
    }

    @Test
    func `parse JWT Invalid Base64URL In Signature`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid@base64"
            )
        }
    }

    @Test
    func `parse JWT Empty Header`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(".eyJzdWIiOiJ0ZXN0In0.sig")
        }
    }

    @Test
    func `parse JWT Empty Payload`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT("eyJhbGciOiJIUzI1NiJ9..sig")
        }
    }

    @Test
    func `serialize JWT`() throws {

        let headerJSON = #"{"alg":"HS256","typ":"JWT"}"#
        let payloadJSON = #"{"sub":"test"}"#
        let signature: [Byte] = [0x01, 0x02, 0x03, 0x04]

        let jwt = try RFC_7519.JWT(
            header: [Byte](headerJSON.utf8),
            payload: [Byte](payloadJSON.utf8),
            signature: signature
        )

        let serialized = String(jwt)

        let parts = serialized.split(separator: ".")
        #expect(parts.count == 3)

        let parsed = try RFC_7519.JWT(serialized)
        #expect(parsed.header == jwt.header)
        #expect(parsed.payload == jwt.payload)
        #expect(parsed.signature == jwt.signature)
    }

    @Test
    func `serialize To Bytes`() throws {
        let headerJSON = #"{"alg":"HS256"}"#
        let payloadJSON = #"{"sub":"user"}"#
        let signature: [Byte] = [0xDE, 0xAD, 0xBE, 0xEF]

        let jwt = try RFC_7519.JWT(
            header: [Byte](headerJSON.utf8),
            payload: [Byte](payloadJSON.utf8),
            signature: signature
        )

        let bytes: [Byte] = Array(jwt)
        #expect(!bytes.isEmpty)

        let string = String(decoding: bytes.underlying, as: UTF8.self)
        #expect(string.split(separator: ".").count == 3)
    }

    @Test
    func `round Trip Preserves Original Base64URL`() throws {
        let originalToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let jwt = try RFC_7519.JWT(originalToken)
        let serialized = String(jwt)

        #expect(serialized == originalToken)
    }

    @Test
    func `round Trip With Newly Created JWT`() throws {
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

    @Test
    func `signing Input Is Correct`() throws {

        let originalToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

        let jwt = try RFC_7519.JWT(originalToken)
        let signingInput = jwt.signingInput

        let signingInputString = String(decoding: signingInput.underlying, as: UTF8.self)
        #expect(
            signingInputString == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        )
    }

    @Test
    func `signing Input Preserves Original Encoding`() throws {

        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

        let jwt = try RFC_7519.JWT(token)
        let signingInput = jwt.signingInput
        let signingInputString = String(decoding: signingInput.underlying, as: UTF8.self)

        #expect(signingInputString == "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
    }

    @Test
    func `create JWT From Components`() throws {
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
    func `create JWT With Empty Header Throws`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                header: [Byte](),
                payload: [Byte](#"{"sub":"test"}"#.utf8),
                signature: [0x01]
            )
        }
    }

    @Test
    func `create JWT With Empty Payload Throws`() {
        #expect(throws: RFC_7519.JWT.Error.self) {
            _ = try RFC_7519.JWT(
                header: [Byte](#"{"alg":"HS256"}"#.utf8),
                payload: [Byte](),
                signature: [0x01]
            )
        }
    }

    @Test
    func `create JWT With Empty Signature Allowed`() throws {

        let jwt = try RFC_7519.JWT(
            header: [Byte](#"{"alg":"none"}"#.utf8),
            payload: [Byte](#"{"sub":"test"}"#.utf8),
            signature: []
        )

        #expect(jwt.signature.isEmpty)
    }

    @Test
    func `jwt Equality`() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig123"

        let jwt1 = try RFC_7519.JWT(token)
        let jwt2 = try RFC_7519.JWT(token)

        #expect(jwt1 == jwt2)
    }

    @Test
    func `jwt Inequality`() throws {
        let token1 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MSJ9.sig1"
        let token2 = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MiJ9.sig2"

        let jwt1 = try RFC_7519.JWT(token1)
        let jwt2 = try RFC_7519.JWT(token2)

        #expect(jwt1 != jwt2)
    }

    @Test
    func `error Descriptions`() {
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

    @Test
    func `init From String`() throws {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }

    @Test
    func `init From Substring`() throws {
        let fullString = "prefix:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl:suffix"
        let token = fullString.dropFirst(7).dropLast(7)

        let jwt = try RFC_7519.JWT(token)

        let headerString = String(decoding: jwt.header.underlying, as: UTF8.self)
        #expect(headerString.contains("HS256"))
    }
}
