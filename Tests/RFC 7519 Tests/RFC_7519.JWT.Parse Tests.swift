import Collection
import Iterator
import Parser
import Testing

@testable import RFC_7519

extension `RFC_7519.JWT Tests` {

    struct Bytes: Sendable {
        let bytes: [UInt8]
        let start: Int
        let end: Int

        init(_ string: String) {
            self.bytes = Array(string.utf8)
            self.start = 0
            self.end = bytes.count
        }

        init(bytes: [UInt8], start: Int, end: Int) {
            self.bytes = bytes
            self.start = start
            self.end = end
        }

        var array: [UInt8] { Array(bytes[start..<end]) }
    }
}

extension `RFC_7519.JWT Tests`.Bytes: Collection.`Protocol` {

    typealias Element = UInt8

    var startIndex: Int { start }

    var endIndex: Int { end }

    subscript(_ position: Int) -> UInt8 { bytes[position] }

    func index(after i: Int) -> Int { i + 1 }

    @_lifetime(borrow self)
    borrowing func makeIterator() -> Iterator::Iterator.Chunk<UInt8> {
        Iterator::Iterator.Chunk(bytes.span.extracting(start..<end))
    }
}

extension `RFC_7519.JWT Tests`.Bytes: Collection.Slice.`Protocol` {

    subscript(bounds: Range<Int>) -> Self {
        Self(bytes: bytes, start: bounds.lowerBound, end: bounds.upperBound)
    }
}

extension `RFC_7519.JWT Tests`.Test {

    private typealias Bytes = `RFC_7519.JWT Tests`.Bytes

    private func byteParse(
        _ token: String
    ) throws(RFC_7519.JWT.Parse<Bytes>.Error) -> RFC_7519.JWT.Parse<Bytes>.Output {
        var input = Bytes(token)
        return try RFC_7519.JWT.Parse<Bytes>().parse(&input)
    }

    @Test
    func `byte Parser Splits Three Segments`() throws {
        let output = try byteParse("aGk.aGk.AQID")

        #expect(output.header.array == Array("aGk".utf8))
        #expect(output.payload.array == Array("aGk".utf8))
        #expect(output.signature.array == Array("AQID".utf8))
    }

    @Test
    func `byte Parser Accepts Empty Signature`() throws {
        let output = try byteParse("aGk.aGk.")

        #expect(output.signature.array.isEmpty)
    }

    @Test
    func `byte Parser Refuses A Fourth Segment`() {
        #expect(throws: RFC_7519.JWT.Parse<Bytes>.Error.unexpectedPeriod) {
            _ = try byteParse("aGk.aGk.AQID.AQID")
        }
    }

    @Test(arguments: [
        "aGk.aGk.AQID",
        "aGk.aGk.",
        "aGk.aGk.AQID.AQID",
        "aGk.aGk",
        ".aGk.AQID",
        "aGk..AQID",
        "aGk",
        "",
        "a.b.c.d",
    ])
    func `byte Parser And Text Parser Agree On Segment Structure`(token: String) {
        let byteAccepts = (try? byteParse(token)) != nil
        let textAccepts = (try? RFC_7519.JWT(token)) != nil

        #expect(byteAccepts == textAccepts)
    }
}
