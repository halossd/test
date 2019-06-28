/// Represents a public key
public struct ETHPublicKey {
    
    /// Public key in data format
    public let raw: Data
    
    public init(raw: Data) {
        self.raw = raw
    }
    
    public init(privateKey: ETHPrivateKey) {
        self.init(raw: Data(hex: "0x") + ETHPublicKey.from(data: privateKey.raw, compressed: false))
    }
    
    /// Address data generated from public key in data format
    private var addressData: Data {
        return ETHCrypto.hashSHA3_256(raw.dropFirst()).suffix(20)
    }
    
    /// generates address from its public key
    ///
    /// - Returns: address in string format
    public func address() -> String {
        return ETHAddress(data: addressData).string
    }
    
    /// Generates public key from specified private key,
    ///
    /// - Parameters: data of private key and compressed
    /// - Returns: Public key in data format
    public static func from(data: Data, compressed: Bool) -> Data {
        return ETHCrypto.generatePublicKey(data: data, compressed: compressed)
    }
}
