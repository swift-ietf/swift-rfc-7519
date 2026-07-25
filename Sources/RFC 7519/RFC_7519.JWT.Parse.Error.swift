//
//  RFC_7519.JWT.Parse.Error.swift
//  swift-rfc-7519
//
//  Public-path alias onto the module-scope `__JWTParserError`.
//

extension RFC_7519.JWT.Parse {
    /// Errors that can occur when parsing a JWT compact serialization.
    public typealias Error = __JWTParserError
}
