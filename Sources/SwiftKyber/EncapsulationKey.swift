//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//

public struct EncapsulationKey: Equatable {
    
    let kyber: Kyber

    // MARK: Stored Properties
    
    /// The key bytes
    public let keyBytes: Bytes


    // MARK: Constructors
    
    /// Creates an encapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Kyber.K512.ekSize {
            self.kyber = Kyber.K512
        } else if keyBytes.count == Kyber.K768.ekSize {
            self.kyber = Kyber.K768
        } else if keyBytes.count == Kyber.K1024.ekSize {
            self.kyber = Kyber.K1024
        } else {
            throw KyberException.encapsulationKeySize(value: keyBytes.count)
        }
        for i in 0 ..< self.kyber.k {
            let ekBytes = Bytes(keyBytes[i * 384 ..< (i + 1) * 384])
            if ekBytes != Kyber.ByteEncode(Kyber.ByteDecode(ekBytes, 12), 12) {
                throw KyberException.encapsulationKeyInconsistent
            }
        }
    }


    // MARK: Instance Methods

    /// The encapsulation function
    ///
    /// - Returns: The shared secret `K` and the ciphertext `ct`
    public func Encapsulate() -> (K: Bytes, ct: Bytes) {
        return self.kyber.ML_KEMEncaps(self.keyBytes)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: EncapsulationKey, key2: EncapsulationKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: EncapsulationKey, key2: EncapsulationKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}
