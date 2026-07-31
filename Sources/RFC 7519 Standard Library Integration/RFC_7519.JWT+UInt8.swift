// RFC_7519.JWT+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for JWT construction from raw bytes. Primary
// byte-domain API lives in `RFC 7519`; this forwarder bridges stdlib callers
// carrying `[UInt8]` (e.g. raw bytes from network frames, base64-decoder
// output) via `.lazy.map(Byte.init)`. Per [API-BYTE-007] (byte-discipline
// skill).

internal import Byte_Primitives
public import RFC_7519

extension RFC_7519.JWT {
    /// Stdlib-interop forwarder: construction from `[UInt8]` components
    /// (e.g., raw bytes from network frames, base64-decoder output).
    @_disfavoredOverload
    // swift-linter:disable:next throwing wrapper init
    // REASON: pure stdlib-interop type bridge per [API-BYTE-007] — converts
    // `[UInt8]` to `[Byte]` and forwards to the byte-domain validating init,
    // which owns the invariant; no additional validation belongs here.
    public init(
        header: [UInt8],
        payload: [UInt8],
        signature: [UInt8]
    ) throws(Error) {
        try self.init(
            header: [Byte](header),
            payload: [Byte](payload),
            signature: [Byte](signature)
        )
    }
}
