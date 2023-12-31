//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//


/// The decapsulation key
public struct DecapsulationKey: Equatable {
    
    let kyber: Kyber
    
    
    // MARK: Initializers
    
    /// Creates a decapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        try self.init(keyBytes, true)
    }

    init(_ keyBytes: Bytes, _ check: Bool) throws {
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
        let encapBytes = self.keyBytes.slice(self.kyber.ekSize - 32, self.kyber.ekSize).bytes
        self.encapsulationKey = try EncapsulationKey(keyBytes: encapBytes)
        if check {
            if Kyber.H(encapBytes) != keyBytes.slice(self.kyber.ekSize * 2 - 32, 32).bytes {
                throw KyberException.decapsulationKeyInconsistent
            }
        }
    }


    // MARK: Stored Properties
    
    /// The key bytes
    public let keyBytes: Bytes
    
    /// The corresponding encapsulation key
    public let encapsulationKey: EncapsulationKey
    
    
    // MARK: Methods

    /// Equality of two decapsulation keys
    ///
    /// - Parameters:
    ///   - key1: a decapsulation key
    ///   - key2: a decapsulation key
    /// - Returns: *true* if key1 and key2 are equal, *false* otherwise
    public static func == (key1: DecapsulationKey, key2: DecapsulationKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// The decapsulation function
    ///
    /// - Parameters:
    ///   - ct: The ciphertext
    /// - Returns: The shared secret
    /// - Throws: A *cipherTextSize* exception if *ct* has wrong size
    public func Decapsulate(ct: Bytes) throws -> Bytes {
        guard ct.count == self.kyber.ctSize else {
            throw KyberException.cipherTextSize(value: ct.count)
        }
        return self.kyber.KEMDecaps(ct, self.keyBytes)
    }

}
