//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import ASN1

/// The internal representation of a public key is a byte array which is the concatenation of two byte arrays called *t* and *rho*.<br/>
/// Please see [KYBER] for clarification.
public struct PublicKey: Equatable, CustomStringConvertible {
    
    let rhoStart: Int
    let kyber: Kyber

    // MARK: Initializers
    
    /// Creates a PublicKey from its key bytes
    ///
    /// - Parameters:
    ///   - bytes: The key bytes
    /// - Throws: An pKSize exception if the key bytes has wrong size
    public init(bytes: Bytes) throws {
        self.bytes = bytes
        self.rhoStart = bytes.count - Kyber.rhoSize
        if bytes.count == Kyber.K512.publicKeySize {
            self.oid = Kyber.K512.OID
            self.kyber = Kyber.K512
        } else if bytes.count == Kyber.K768.publicKeySize {
            self.oid = Kyber.K768.OID
            self.kyber = Kyber.K768
        } else if bytes.count == Kyber.K1024.publicKeySize {
            self.oid = Kyber.K1024.OID
            self.kyber = Kyber.K1024
        } else {
            throw KyberException.pkSize(value: bytes.count)
        }
    }
    
    /// Creates a PublicKey from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    /// - Throws: An exception if the DER encoding is wrong
    public init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let sequence1 = asn1 as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence1.getValue().count == 2 else {
            throw KyberException.asn1Structure
        }
        guard let sequence2 = sequence1.get(0) as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence2.getValue().count > 0 else {
            throw KyberException.asn1Structure
        }
        guard let oid = sequence2.get(0) as? ASN1ObjectIdentifier else {
            throw KyberException.asn1Structure
        }
        guard let bitString = sequence1.get(1) as? ASN1BitString else {
            throw KyberException.asn1Structure
        }
        guard let sequence3 = try ASN1.build(bitString.bits) as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence3.getValue().count == 2 else {
            throw KyberException.asn1Structure
        }
        guard let t = sequence3.get(0) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let rho = sequence3.get(1) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        let bytes = t.value + rho.value
        if (oid == Kyber.K512.OID && bytes.count == Kyber.K512.publicKeySize)
            || (oid == Kyber.K768.OID && bytes.count == Kyber.K768.publicKeySize)
            || (oid == Kyber.K1024.OID && bytes.count == Kyber.K1024.publicKeySize) {
            try self.init(bytes: bytes)
        } else {
            throw KyberException.asn1Structure
        }
    }

    /// Creates a PublicKey from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        try self.init(der: Base64.pemDecode(pem, "PUBLIC KEY"))
    }


    // MARK: Stored Properties
    
    /// The raw key bytes
    public let bytes: Bytes

    /// The Kyber OID
    public let oid: ASN1ObjectIdentifier

    
    // MARK: Computed Properties

    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }

    /// The ASN1 encoding of *self*
    public var asn1: ASN1 { get { do {
        return ASN1Sequence()
            .add(ASN1Sequence().add(self.oid))
            .add(try ASN1BitString(
                ASN1Sequence()
                    .add(ASN1OctetString(self.t))
                    .add(ASN1OctetString(self.rho)).encode(),
                0))
    }  catch { return ASN1.NULL} } }
    
    /// The DER encoding of *self*
    public var der: Bytes { get { return self.asn1.encode() } }
    
    /// The PEM base 64 encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.der, "PUBLIC KEY") } }
    
    /// The t part of *self*
    public var t: Bytes { get { return Bytes(self.bytes[0 ..< self.rhoStart]) } }
    
    /// The rho part of *self*
    public var rho: Bytes { get { return Bytes(self.bytes[self.rhoStart ..< self.bytes.count]) } }
    
    
    // MARK: Methods

    /// Equality
    ///
    /// - Parameters:
    ///   - x: First key
    ///   - y: Second key
    /// - Returns: *true* if x = y, *false* otherwise
    public static func ==(x: PublicKey, y: PublicKey) -> Bool {
        return x.oid == y.oid && x.bytes == y.bytes
    }

    /// The encapsulation function
    ///
    /// - Returns: The ciphertext *ct* and the shared secret *K*
    public func Encapsulate() -> (ct: Bytes, K: Bytes) {
        return self.kyber.CCAKEM_Enc(self, [])
    }
    
}
