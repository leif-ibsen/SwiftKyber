//
//  File.swift
//  
//
//  Created by Leif Ibsen on 25/12/2023.
//

import ASN1
import Digest

public struct DecapsulationKey: Equatable, CustomStringConvertible {
    
    let kyber: Kyber

    // MARK: Stored Properties
    
    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The corresponding encapsulation key
    public internal(set) var encapsulationKey: EncapsulationKey
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1.ZERO).add(ASN1Sequence().add(self.kyber.oid)).add(ASN1OctetString(ASN1OctetString(self.keyBytes).encode())) } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }


    // MARK: Constructors
    
    init(_ keyBytes: Bytes, _ kyber: Kyber) throws {
        self.keyBytes = keyBytes
        self.kyber = kyber
        let encapBytes = Bytes(self.keyBytes[self.kyber.kx384 ..< self.kyber.kx768 + 32])
        if Kyber.H(encapBytes) != Bytes(keyBytes[self.kyber.kx768 + 32 ..< self.kyber.kx768 + 64]) {
            throw Exception.decapsulationKeyInconsistent
        }
        self.encapsulationKey = try EncapsulationKey(keyBytes: encapBytes)
    }

    /// Creates a decapsulation key from its key bytes
    ///
    /// - Parameters:
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(keyBytes: Bytes) throws {
        for kind in Kind.allCases {
            if keyBytes.count == Parameters.paramsFromKind(kind).dkSize {
                try self.init(keyBytes, Kyber(kind))
                return
            }
        }
        throw Exception.decapsulationKeySize(value: keyBytes.count)
    }

    /// Creates a decapsulation key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The decapsulation key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PRIVATE KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw Exception.asn1Structure
        }
        guard let int = seq.get(0) as? ASN1Integer else {
            throw Exception.asn1Structure
        }
        if int != ASN1.ZERO {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let octets = seq.get(2) as? ASN1OctetString else {
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
        guard let seq2 = try ASN1.build(octets.value) as? ASN1OctetString else {
            throw Exception.asn1Structure
        }
        try self.init(seq2.value, Kyber(kind))
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
            throw Exception.cipherTextSize(value: ct.count)
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
