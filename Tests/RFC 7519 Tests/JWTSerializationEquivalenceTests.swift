import Binary_Serializable
import Testing

@testable import RFC_7519

extension RFC_7519.JWT {
    @Suite
    struct Test {

        @Test
        func `ascii Verb Output Equals Binary Witness Output For The Base64URL Encode Path`() throws
        {

            let jwt = try RFC_7519.JWT(
                header: [0xFF, 0xFF, 0xBF],
                payload: [0xFB, 0xF0],
                signature: [0xFF, 0xEF, 0xFB]
            )

            let viaASCII: [Byte] = jwt.serialized

            var viaBinary: [Byte] = []
            RFC_7519.JWT.serialize(jwt, into: &viaBinary)

            #expect(viaASCII == viaBinary)

            let text = String(decoding: viaASCII.underlying, as: UTF8.self)
            #expect(text.contains("-"))
            #expect(text.contains("_"))
        }
    }
}
