import Parser

extension IETF.RFC.`7519`.JWT.Parse {
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
