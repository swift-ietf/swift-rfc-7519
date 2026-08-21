public import Parser_Primitives

extension RFC_7519.JWT {

    public struct Parse<Input: Collection.Slice.`Protocol`>: Sendable
    where Input: Sendable, Input.Element == UInt8 {
        @inlinable
        public init() {}
    }
}

extension RFC_7519.JWT.Parse: Parser.`Protocol` {
    public typealias Failure = __JWTParserError

    public typealias Body = Never

    @inlinable
    public func parse(_ input: inout Input) throws(Failure) -> Output {
        let header = try _consumeSegment(&input)
        try _expectPeriod(&input)
        let payload = try _consumeSegment(&input)
        try _expectPeriod(&input)

        let signature = input[input.startIndex..<input.endIndex]
        input = input[input.endIndex...]

        return Output(header: header, payload: payload, signature: signature)
    }

    @inlinable
    package func _consumeSegment(_ input: inout Input) throws(Failure) -> Input {
        var index = input.startIndex
        while index < input.endIndex {
            if input[index] == 0x2E { break }
            input.formIndex(after: &index)
        }
        guard index > input.startIndex else { throw .emptySegment }
        let result = input[input.startIndex..<index]
        input = input[index...]
        return result
    }

    @inlinable
    package func _expectPeriod(_ input: inout Input) throws(Failure) {
        guard input.startIndex < input.endIndex,
            input[input.startIndex] == 0x2E
        else {
            throw .expectedPeriod
        }
        input = input[input.index(after: input.startIndex)...]
    }
}
