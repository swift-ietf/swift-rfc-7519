# swift-rfc-7519

Use this package when you need to split a JSON Web Token in compact form into its header, payload and signature, or to put one together from those parts. Start from `RFC_7519.JWT`. Header and payload are kept as raw bytes. The package does not parse their JSON, check claims such as expiry, or create and verify signatures, so you sign `RFC_7519.JWT.signingInput` with your own key and code.

## Laws

- A token must be ASCII with exactly two periods. The header and payload must not be empty. The signature may be empty, as in an unsecured token such as `eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.`.
- Each part must be valid Base64URL, or parsing fails with `RFC_7519.JWT.Error.invalidBase64URL(_:component:)` naming the part.
- A parsed token keeps the Base64URL text of its header and payload exactly as received. `RFC_7519.JWT.signingInput` and the token's text form use that text, so a parsed token prints back unchanged and its signing input is the one the issuer signed.
- A token built from bytes encodes its header and payload once, when it is created. The signature is always written as unpadded Base64URL.
- Two tokens are equal when their decoded header, payload and signature bytes are equal, whatever Base64URL spelling they were read from.
