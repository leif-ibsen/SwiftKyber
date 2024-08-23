//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//

public struct DecapsulationKey: Equatable {
    
    let kyber: Kyber
    
    // MARK: Stored Properties
    
    /// The key bytes
    public let keyBytes: Bytes
    
    /// The corresponding encapsulation key
    public let encapsulationKey: EncapsulationKey
    

    // MARK: Constructors
    
    /// Creates a decapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        self.keyBytes = keyBytes
        if keyBytes.count == Kyber.K512.dkSize {
            self.kyber = Kyber.K512
        } else if keyBytes.count == Kyber.K768.dkSize {
            self.kyber = Kyber.K768
        } else if keyBytes.count == Kyber.K1024.dkSize {
            self.kyber = Kyber.K1024
        } else {
            throw KyberException.decapsulationKeySize(value: keyBytes.count)
        }
        let encapBytes = Bytes(self.keyBytes[self.kyber.k384 ..< self.kyber.k768 + 32])
        if Kyber.H(encapBytes) != Bytes(keyBytes[self.kyber.k768 + 32 ..< self.kyber.k768 + 64]) {
            throw KyberException.decapsulationKeyInconsistent
        }
        self.encapsulationKey = try EncapsulationKey(keyBytes: encapBytes)
    }


    // MARK: Instance Methods

    /// The decapsulation function
    ///
    /// - Parameters:
    ///   - ct: The ciphertext
    /// - Returns: The shared secret
    /// - Throws: An exception if the ciphertext has wrong size
    public func Decapsulate(ct: Bytes) throws -> Bytes {
        guard ct.count == self.kyber.ctSize else {
            throw KyberException.cipherTextSize(value: ct.count)
        }
        return self.kyber.ML_KEMDecaps(self.keyBytes, ct)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: DecapsulationKey, key2: DecapsulationKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: DecapsulationKey, key2: DecapsulationKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}
