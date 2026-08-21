internal import Byte_Primitives
public import RFC_7519

extension RFC_7519.JWT {

    @_disfavoredOverload

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
