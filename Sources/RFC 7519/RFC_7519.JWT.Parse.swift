//
//  RFC_7519.JWT.Parse.swift
//  swift-rfc-7519
//
//  JWT Compact Serialization: base64url.base64url.base64url
//

public import Parser_Primitives

extension RFC_7519.JWT {
    /// Parses a JWT compact serialization per RFC 7519 Section 3.1.
    ///
    /// `compact = BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)`
    ///
    /// Returns three raw slices (Base64URL-encoded). Decoding is left to the caller.
    public struct Parse<Input: Collection.Slice.`Protocol`>: Sendable
    where Input: Sendable, Input.Element == UInt8 {
        @inlinable
        public init() {}
    }
}

extension RFC_7519.JWT.Parse {
    public struct Output: Sendable {
        public let header: Input
        public let payload: Input
        public let signature: Input

        @inlinable
        public init(header: Input, payload: Input, signature: Input) {
            self.header = header
            self.payload = payload
            self.signature = signature
        }
    }

    public enum Error: Swift.Error, Sendable, Equatable {
        case expectedPeriod
        case emptySegment
    }
}

extension RFC_7519.JWT.Parse: Parser.`Protocol` {
    public typealias Failure = RFC_7519.JWT.Parse<Input>.Error

    @inlinable
    public func parse(_ input: inout Input) throws(Failure) -> Output {
        let header = try _consumeSegment(&input)
        try _expectPeriod(&input)
        let payload = try _consumeSegment(&input)
        try _expectPeriod(&input)

        // Signature is the rest
        let signature = input[input.startIndex..<input.endIndex]
        input = input[input.endIndex...]

        return Output(header: header, payload: payload, signature: signature)
    }

    @inlinable
    func _consumeSegment(_ input: inout Input) throws(Failure) -> Input {
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
    func _expectPeriod(_ input: inout Input) throws(Failure) {
        guard input.startIndex < input.endIndex,
            input[input.startIndex] == 0x2E else {
            throw .expectedPeriod
        }
        input = input[input.index(after: input.startIndex)...]
    }
}
