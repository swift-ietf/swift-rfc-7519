import Binary
import Testing

@testable import RFC_7519

enum `IETF.RFC.7519.JWT Tests` {}

extension `IETF.RFC.7519.JWT Tests` {
    @Suite
    struct Test {

        @Test
        func `ascii Verb Output Equals Binary Witness Output For The Base64URL Encode Path`() throws {

            let jwt = try IETF.RFC.`7519`.JWT(
                header: [Byte(0xFF), Byte(0xFF), Byte(0xBF)],
                payload: [Byte(0xFB), Byte(0xF0)],
                signature: [Byte(0xFF), Byte(0xEF), Byte(0xFB)]
            )

            let viaASCII: [Byte] = jwt.serialized

            var viaBinary: [Byte] = []
            IETF.RFC.`7519`.JWT.serialize(jwt, into: &viaBinary)

            #expect(viaASCII == viaBinary)

            let text = String(decoding: viaASCII, as: UTF8.self)
            #expect(text.contains("-"))
            #expect(text.contains("_"))
        }
    }
}
