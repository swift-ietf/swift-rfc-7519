import Foundation
import Testing

@testable import RFC_7519

extension `RFC_7519.JWT Tests`.Test {

    @Test
    func `codable Encodes Compact Text`() throws {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.AQID"
        let jwt = try RFC_7519.JWT(token)

        let data = try JSONEncoder().encode([jwt])

        #expect(String(decoding: data, as: UTF8.self) == "[\"\(token)\"]")
    }

    @Test
    func `codable Round Trips`() throws {
        let jwt = try RFC_7519.JWT(
            header: [Byte](utf8: #"{"alg":"none"}"#),
            payload: [Byte](utf8: #"{"sub":"test"}"#),
            signature: [Byte(0x01), Byte(0x02), Byte(0x03)]
        )

        let decoded = try JSONDecoder().decode([RFC_7519.JWT].self, from: JSONEncoder().encode([jwt]))

        #expect(decoded == [jwt])
    }

    @Test
    func `codable Decoding Refuses Empty Header`() {
        let data = Data(#"[".eyJzdWIiOiJ0ZXN0In0.AQID"]"#.utf8)

        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode([RFC_7519.JWT].self, from: data)
        }
    }

    @Test
    func `codable Decoding Refuses Empty Payload`() {
        let data = Data(#"["eyJhbGciOiJub25lIn0..AQID"]"#.utf8)

        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode([RFC_7519.JWT].self, from: data)
        }
    }

    @Test
    func `codable Decoding Refuses An Object Of Stored Properties`() {
        let data = Data(#"[{"header":[1],"payload":[1],"signature":[]}]"#.utf8)

        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode([RFC_7519.JWT].self, from: data)
        }
    }
}
