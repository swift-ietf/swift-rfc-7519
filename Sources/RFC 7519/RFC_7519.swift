// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7519 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

/// RFC 7519: JSON Web Token (JWT)
///
/// This module provides Swift types for RFC 7519 compliant JSON Web Tokens.
///
/// JWTs are a compact, URL-safe means of representing claims to be transferred
/// between two parties.
///
/// ## Overview
///
/// A JWT consists of three parts separated by dots:
/// - Header: Contains the token type and signing algorithm
/// - Payload: Contains the claims (statements about an entity)
/// - Signature: Used to verify the message wasn't changed
///
/// ## Key Types
///
/// - ``JWT``: A complete JSON Web Token
/// - ``JWT/Header``: The JWT header containing algorithm and type
/// - ``JWT/Payload``: The JWT payload containing claims
///
/// ## Example
///
/// ```swift
/// // Parse a JWT from its compact serialization
/// let jwt = try RFC_7519.JWT(ascii: tokenString.utf8)
///
/// // Access claims
/// print(jwt.payload.iss)  // Issuer
/// print(jwt.payload.sub)  // Subject
/// print(jwt.payload.exp)  // Expiration
/// ```
///
/// ## RFC Reference
///
/// - [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)
/// - References: RFC 7515 (JWS), RFC 7516 (JWE), RFC 7518 (JWA)
public enum RFC_7519 {}
