import CryptoEthereumSwift

public struct ETHHDPrivateKey {
    public let raw: Data
    public let chainCode: Data
    private let depth: UInt8
    private let fingerprint: UInt32
    private let childIndex: UInt32
    private let network: ETHNetwork
    
    public init(seed: Data, network: ETHNetwork) {
        let output = ETHCrypto.HMACSHA512(key: "Bitcoin seed".data(using: .ascii)!, data: seed)
        self.raw = output[0..<32]
        self.chainCode = output[32..<64]
        self.depth = 0
        self.fingerprint = 0
        self.childIndex = 0
        self.network = network
    }
    
    private init(hdPrivateKey: Data, chainCode: Data, depth: UInt8, fingerprint: UInt32, index: UInt32, network: ETHNetwork) {
        self.raw = hdPrivateKey
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = index
        self.network = network
    }
    
    public func privateKey() -> ETHPrivateKey {
        return ETHPrivateKey(raw: Data(hex: "0x") + raw)
    }
    
    public func hdPublicKey() -> ETHHDPublicKey {
        return ETHHDPublicKey(hdPrivateKey: self, chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
    }
    
    public func extended() -> String {
        var extendedPrivateKeyData = Data()
        extendedPrivateKeyData += network.privateKeyPrefix.bigEndian
        extendedPrivateKeyData += depth.littleEndian
        extendedPrivateKeyData += fingerprint.littleEndian
        extendedPrivateKeyData += childIndex.littleEndian
        extendedPrivateKeyData += chainCode
        extendedPrivateKeyData += UInt8(0)
        extendedPrivateKeyData += raw
        let checksum = ETHCrypto.doubleSHA256(extendedPrivateKeyData).prefix(4)
        return Base58.encode(extendedPrivateKeyData + checksum)
    }
    
    internal func derived(at index: UInt32, hardens: Bool = false) throws -> ETHHDPrivateKey {
        guard (0x80000000 & index) == 0 else {
            fatalError("Invalid index \(index)")
        }
        
        let keyDeriver = KeyDerivation(
            privateKey: raw,
            publicKey: hdPublicKey().raw,
            chainCode: chainCode,
            depth: depth,
            fingerprint: fingerprint,
            childIndex: childIndex
        )
        
        guard let derivedKey = keyDeriver.derived(at: index, hardened: hardens) else {
            throw EthereumKitError.cryptoError(.keyDerivateionFailed)
        }
        
        return ETHHDPrivateKey(
            hdPrivateKey: derivedKey.privateKey!,
            chainCode: derivedKey.chainCode,
            depth: derivedKey.depth,
            fingerprint: derivedKey.fingerprint,
            index: derivedKey.childIndex,
            network: network
        )
    }
}
