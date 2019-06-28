public struct ETHHDPublicKey {
    public let raw: Data
    public let chainCode: Data
    private let depth: UInt8
    private let fingerprint: UInt32
    private let childIndex: UInt32
    private let network: ETHNetwork
    
    private let hdPrivateKey: ETHHDPrivateKey
    
    public init(hdPrivateKey: ETHHDPrivateKey, chainCode: Data, network: ETHNetwork, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.raw = ETHPublicKey.from(data: hdPrivateKey.raw, compressed: true)
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
        self.network = network
        self.hdPrivateKey = hdPrivateKey
    }
    
    public func publicKey() -> ETHPublicKey {
        return ETHPublicKey(privateKey: hdPrivateKey.privateKey())
    }
    
    public func extended() -> String {
        var extendedPublicKeyData = Data()
        extendedPublicKeyData += network.publicKeyPrefix.bigEndian
        extendedPublicKeyData += depth.littleEndian
        extendedPublicKeyData += fingerprint.littleEndian
        extendedPublicKeyData += childIndex.littleEndian
        extendedPublicKeyData += chainCode
        extendedPublicKeyData += raw
        let checksum = ETHCrypto.doubleSHA256(extendedPublicKeyData).prefix(4)
        return Base58.encode(extendedPublicKeyData + checksum)
    }
}
