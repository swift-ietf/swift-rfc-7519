//
//  RFC_7519.__JWTParserError.swift
//  swift-rfc-7519
//
//  Module-scope, non-generic error for the RFC 7519 JWT compact-serialization parser.
//
//  Hoisted out of the generic `RFC_7519.JWT.Parse<Input>` namespace so the
//  `@error` SIL result carries no phantom `Input` type parameter — the structural
//  fix for the `FunctionSignatureOpts` release-build ICE
//  (`SILArgument.cpp:40 !type.hasTypeParameter()`; Research §A13 / swiftlang/swift#89617).
//  Surfaced through the public path `RFC_7519.JWT.Parse.Error` (a typealias).
//

/// Errors that can occur when parsing a JWT compact serialization.
public enum __JWTParserError: Swift.Error, Sendable, Equatable {
    /// The input did not contain the required `.` separator between segments.
    case expectedPeriod
    /// A segment of the compact serialization was empty.
    case emptySegment
}
