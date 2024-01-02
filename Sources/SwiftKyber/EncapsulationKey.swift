//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//

/// The encapsulation key
public struct EncapsulationKey: Equatable {
    
    let kyber: Kyber

    
    // MARK: Initializers
    
    /// Creates an encapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        try self.init(keyBytes, true)
    }

    init(_ keyBytes: Bytes, _ check: Bool) throws {
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
        if check {
            var x = self.keyBytes.slice(0, 384)
            for _ in 0 ..< self.kyber.k {
                if x.bytes != Kyber.ByteEncode(Kyber.ByteDecode(x.bytes, 12), 12) {
                    throw KyberException.encapsulationKeyInconsistent
                }
                x.next()
            }
        }
    }


    // MARK: Stored Properties
    
    /// The key bytes
    public let keyBytes: Bytes

    
    // MARK: Methods

    /// Equality of two encapsulation keys
    ///
    /// - Parameters:
    ///   - key1: an encapsulation key
    ///   - key2: an encapsulation key
    /// - Returns: *true* if key1 and key2 are equal, *false* otherwise
    public static func == (key1: EncapsulationKey, key2: EncapsulationKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// The encapsulation function
    ///
    /// - Returns: The shared secret *K* and the ciphertext *ct*
    public func Encapsulate() -> (K: Bytes, ct: Bytes) {
        return self.kyber.KEMEncaps([], self.keyBytes)
    }

    // Only used from the KAT test cases
    func Encapsulate(_ seed: Bytes) -> (K: Bytes, ct: Bytes) {
        return self.kyber.KEMEncaps(seed, self.keyBytes)
    }
    
}
