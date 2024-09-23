//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//

import ASN1
import Digest

public struct EncapsulationKey: Equatable, CustomStringConvertible {
    
    let kyber: Kyber

    // MARK: Stored Properties
    
    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return ASN1Sequence().add(ASN1Sequence().add(self.kyber.oid)).add(try ASN1BitString(self.keyBytes, 0)) } catch { return ASN1.NULL } } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PUBLIC KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }


    // MARK: Constructors
    
    init(_ keyBytes: Bytes, _ kyber: Kyber) throws {
        self.keyBytes = keyBytes
        self.kyber = kyber
        for i in 0 ..< self.kyber.k {
            let ekBytes = Bytes(keyBytes[i * 384 ..< (i + 1) * 384])
            if ekBytes != Kyber.ByteEncode(Kyber.ByteDecode(ekBytes, 12), 12) {
                throw Exception.encapsulationKeyInconsistent
            }
        }
    }

    /// Creates an encapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        for kind in Kind.allCases {
            if keyBytes.count == Parameters.paramsFromKind(kind).ekSize {
                try self.init(keyBytes, Kyber(kind))
                return
            }
        }
        throw Exception.encapsulationKeySize(value: keyBytes.count)
    }

    /// Creates an encapsulation key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The encapsulation key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PUBLIC KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 2 {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(0) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let bits = seq.get(1) as? ASN1BitString else {
            throw Exception.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Exception.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Exception.asn1Structure
        }
        guard let kind = Parameters.kindFromOID(oid) else {
            throw Exception.asn1Structure
        }
        guard bits.unused == 0 else {
            throw Exception.asn1Structure
        }
        try self.init(bits.bits, Kyber(kind))
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
