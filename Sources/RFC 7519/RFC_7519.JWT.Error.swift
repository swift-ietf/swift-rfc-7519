extension RFC_7519.JWT {

    public enum Error: Swift.Error, Sendable, Equatable, CustomStringConvertible {
        case empty
        case emptyHeader
        case emptyPayload
        case invalidFormat(_ value: String)
        case invalidBase64URL(_ value: String, component: String)
    }
}

extension RFC_7519.JWT.Error {
    public var description: String {
        switch self {
        case .empty:
            return "JWT cannot be empty"

        case .emptyHeader:
            return "JWT header cannot be empty"

        case .emptyPayload:
            return "JWT payload cannot be empty"

        case .invalidFormat(let value):
            return "Invalid JWT format (expected header.payload.signature): '\(value)'"

        case .invalidBase64URL(let value, let component):
            return "Invalid Base64URL encoding in JWT \(component): '\(value)'"
        }
    }
}
