internal import Byte
public import RFC_7519

extension RFC_7519.JWT {

    @_disfavoredOverload

    public init(
        header: [UInt8],
        payload: [UInt8],
        signature: [UInt8]
    ) throws(Error) {
        try self.init(
            header: header.map(Byte.init(bitPattern:)),
            payload: payload.map(Byte.init(bitPattern:)),
            signature: signature.map(Byte.init(bitPattern:))
        )
    }
}
