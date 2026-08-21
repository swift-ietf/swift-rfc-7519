import Parser_Primitives

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
}
