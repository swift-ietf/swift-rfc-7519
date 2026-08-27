public import ASCII_Serializer
public import Binary_Serializable
public import Parseable_ASCII

extension RFC_7519 {

    public struct JWT: Sendable, Codable {

        public let header: [Byte]

        public let payload: [Byte]

        public let signature: [Byte]

        package let headerBase64URL: [Byte]

        package let payloadBase64URL: [Byte]

        private init(
            __unchecked: Void,
            header: [Byte],
            payload: [Byte],
            signature: [Byte],
            headerBase64URL: [Byte],
            payloadBase64URL: [Byte]
        ) {
            self.header = header
            self.payload = payload
            self.signature = signature
            self.headerBase64URL = headerBase64URL
            self.payloadBase64URL = payloadBase64URL
        }

        public init(
            header: [Byte],
            payload: [Byte],
            signature: [Byte]
        ) throws(Error) {
            guard !header.isEmpty else {
                throw Error.emptyHeader
            }
            guard !payload.isEmpty else {
                throw Error.emptyPayload
            }

            let headerBase64URL = [Byte](RFC_4648.Base64.URL.encode(header))
            let payloadBase64URL = [Byte](RFC_4648.Base64.URL.encode(payload))

            self.init(

                __unchecked: (),
                header: header,
                payload: payload,
                signature: signature,
                headerBase64URL: headerBase64URL,
                payloadBase64URL: payloadBase64URL
            )
        }

    }
}

extension RFC_7519.JWT {

    public var signingInput: [Byte] {
        var result: [Byte] = []
        result.reserveCapacity(headerBase64URL.count + 1 + payloadBase64URL.count)
        result.append(contentsOf: headerBase64URL)

        result.append(ASCII.Code.period)
        result.append(contentsOf: payloadBase64URL)
        return result
    }
}

extension RFC_7519.JWT: ASCII.Parseable {

    public init(_ string: some StringProtocol) throws(Error) {
        try self.init(ascii: [Byte](string.utf8))
    }

    public init<Bytes: Swift.Collection>(ascii bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {

        let arr: [ASCII.Code]
        do throws(ASCII.Code.Error) {
            arr = try [ASCII.Code](bytes)
        } catch {
            throw Error.invalidFormat(String(decoding: bytes, as: UTF8.self))
        }
        guard !arr.isEmpty else { throw Error.empty }

        var firstPeriodIndex: Int?
        var secondPeriodIndex: Int?

        for (index, code) in arr.enumerated() {
            if code == ASCII.Code.period {
                if firstPeriodIndex == nil {
                    firstPeriodIndex = index
                } else if secondPeriodIndex == nil {
                    secondPeriodIndex = index
                } else {

                    throw Error.invalidFormat(String(decoding: arr, as: UTF8.self))
                }
            }
        }

        guard let first = firstPeriodIndex, let second = secondPeriodIndex else {
            throw Error.invalidFormat(String(decoding: arr, as: UTF8.self))
        }

        let headerBase64URLCodes = Array(arr[..<first])
        let payloadBase64URLCodes = Array(arr[(first + 1)..<second])
        let signatureBase64URLCodes = Array(arr[(second + 1)...])

        guard !headerBase64URLCodes.isEmpty else {
            throw Error.emptyHeader
        }
        guard let header = RFC_4648.Base64.URL.decode(headerBase64URLCodes) else {
            throw Error.invalidBase64URL(
                String(decoding: headerBase64URLCodes, as: UTF8.self),
                component: "header"
            )
        }

        guard !payloadBase64URLCodes.isEmpty else {
            throw Error.emptyPayload
        }
        guard let payload = RFC_4648.Base64.URL.decode(payloadBase64URLCodes) else {
            throw Error.invalidBase64URL(
                String(decoding: payloadBase64URLCodes, as: UTF8.self),
                component: "payload"
            )
        }

        let signature: [Byte]
        if signatureBase64URLCodes.isEmpty {
            signature = []
        } else {
            guard let decoded = RFC_4648.Base64.URL.decode(signatureBase64URLCodes) else {
                throw Error.invalidBase64URL(
                    String(decoding: signatureBase64URLCodes, as: UTF8.self),
                    component: "signature"
                )
            }
            signature = decoded
        }

        self.init(

            __unchecked: (),
            header: header,
            payload: payload,
            signature: signature,
            headerBase64URL: [Byte](headerBase64URLCodes),
            payloadBase64URL: [Byte](payloadBase64URLCodes)
        )
    }
}

extension RFC_7519.JWT: ASCII.Serializable, Binary.Serializable {

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == ASCII.Code {
        buffer.append(contentsOf: value.headerBase64URL.map { ASCII.Code(unchecked: $0) })
        buffer.append(ASCII.Code.period)
        buffer.append(contentsOf: value.payloadBase64URL.map { ASCII.Code(unchecked: $0) })
        buffer.append(ASCII.Code.period)

        RFC_4648.Base64.URL.encode(value.signature, into: &buffer, padding: false)
    }

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        serializeBytes(value, into: &buffer)
    }

    private static func serializeBytes<Buffer: RangeReplaceableCollection>(
        _ jwt: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(contentsOf: jwt.headerBase64URL)
        buffer.append(ASCII.Code.period)
        buffer.append(contentsOf: jwt.payloadBase64URL)
        buffer.append(ASCII.Code.period)

        var signatureEncoded: [ASCII.Code] = []
        RFC_4648.Base64.URL.encode(jwt.signature, into: &signatureEncoded, padding: false)
        buffer.append(contentsOf: signatureEncoded)
    }
}

extension RFC_7519.JWT: Swift.RawRepresentable {

    public var rawValue: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }

    public init?(rawValue: String) {
        do throws(Error) {
            try self.init(rawValue)
        } catch {
            return nil
        }
    }
}

extension RFC_7519.JWT: CustomStringConvertible {

    public var description: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }
}

extension RFC_7519.JWT: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(header)
        hasher.combine(payload)
        hasher.combine(signature)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.header == rhs.header
            && lhs.payload == rhs.payload
            && lhs.signature == rhs.signature
    }
}
