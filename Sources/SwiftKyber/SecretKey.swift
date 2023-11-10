//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import ASN1

/// The internal representation of a secret key is a byte array which is the concatenation of five byte arrays called *s*, *t*, *rho*, *h* and *z*.<br/>
/// Please see [KYBER] for clarification.
public struct SecretKey: Equatable, CustomStringConvertible {
    
    let tStart: Int
    let rhoStart: Int
    let hStart: Int
    let zStart: Int
    let kyber: Kyber
    
    
    // MARK: Initializers
    
    /// Creates a SecretKey from its key bytes
    ///
    /// - Parameters:
    ///   - bytes: The key bytes
    /// - Throws: An exception if the key bytes are inconsistent or has wrong size
    public init(bytes: Bytes) throws {
        self.bytes = bytes
        if bytes.count == Kyber.K512.secretKeySize {
            self.oid = Kyber.K512.OID
            self.kyber = Kyber.K512
            self.tStart = Kyber.K512.sSize
            self.rhoStart = self.tStart + Kyber.K512.tSize
            self.hStart = self.rhoStart + Kyber.rhoSize
            self.zStart = self.hStart + Kyber.hSize
        } else if bytes.count == Kyber.K768.secretKeySize {
            self.oid = Kyber.K768.OID
            self.kyber = Kyber.K768
            self.tStart = Kyber.K768.sSize
            self.rhoStart = self.tStart + Kyber.K768.tSize
            self.hStart = self.rhoStart + Kyber.rhoSize
            self.zStart = self.hStart + Kyber.hSize
        } else if bytes.count == Kyber.K1024.secretKeySize {
            self.oid = Kyber.K1024.OID
            self.kyber = Kyber.K1024
            self.tStart = Kyber.K1024.sSize
            self.rhoStart = self.tStart + Kyber.K1024.tSize
            self.hStart = self.rhoStart + Kyber.rhoSize
            self.zStart = self.hStart + Kyber.hSize
        } else {
            throw KyberException.skSize(value: bytes.count)
        }
        let pkBytes = Bytes(self.bytes[self.tStart ..< self.hStart])
        if self.kyber.H(pkBytes) != Bytes(bytes[self.hStart ..< self.zStart]) {
            throw KyberException.skInconsistent
        }
        self.publicKey = try PublicKey(bytes: pkBytes)
    }

    /// Creates a SecretKey from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    /// - Throws: An exception if the DER encoding is wrong
    public init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let sequence1 = asn1 as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence1.getValue().count >= 3 else {
            throw KyberException.asn1Structure
        }
        guard let version1 = sequence1.get(0) as? ASN1Integer else {
            throw KyberException.asn1Structure
        }
        guard version1 == ASN1.ZERO else {
            throw KyberException.asn1Structure
        }
        guard let sequence2 = sequence1.get(1) as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence2.getValue().count > 0 else {
            throw KyberException.asn1Structure
        }
        guard let oid = sequence2.get(0) as? ASN1ObjectIdentifier else {
            throw KyberException.asn1Structure
        }
        guard let privOctets = sequence1.get(2) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let sequence3 = try ASN1.build(privOctets.value) as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard sequence3.getValue().count == 5 else {
            throw KyberException.asn1Structure
        }
        guard let version2 = sequence3.get(0) as? ASN1Integer else {
            throw KyberException.asn1Structure
        }
        guard version2 == ASN1.ZERO else {
            throw KyberException.asn1Structure
        }
        guard let sBytes = sequence3.get(1) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let ctx = sequence3.get(2) as? ASN1Ctx else {
            throw KyberException.asn1Structure
        }
        guard let sequence4 = try ASN1.build(ctx.bytes!) as? ASN1Sequence else {
            throw KyberException.asn1Structure
        }
        guard let tBytes = sequence4.get(0) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let rhoBytes = sequence4.get(1) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let hBytes = sequence3.get(3) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        guard let zBytes = sequence3.get(4) as? ASN1OctetString else {
            throw KyberException.asn1Structure
        }
        try SecretKey.checkKey(oid, sBytes.value.count, tBytes.value.count, rhoBytes.value.count, hBytes.value.count, zBytes.value.count)
        try self.init(bytes: sBytes.value + tBytes.value + rhoBytes.value + hBytes.value + zBytes.value)
    }

    static func checkKey(_ oid: ASN1ObjectIdentifier, _ sSize: Int, _ tSize: Int, _ rhoSize: Int, _ hSize: Int, _ zSize: Int) throws {
        if hSize != Kyber.hSize{
            throw KyberException.skInconsistent
        }
        if zSize != Kyber.zSize {
            throw KyberException.skInconsistent
        }
        if oid == Kyber.K512.OID {
            if sSize != Kyber.K512.sSize {
                throw KyberException.skInconsistent
            }
            if tSize + rhoSize != Kyber.K512.publicKeySize {
                throw KyberException.skInconsistent
            }
        } else if oid == Kyber.K768.OID {
            if sSize != Kyber.K768.sSize {
                throw KyberException.skInconsistent
            }
            if tSize + rhoSize != Kyber.K768.publicKeySize {
                throw KyberException.skInconsistent
            }
        } else if oid == Kyber.K1024.OID {
            if sSize != Kyber.K1024.sSize {
                throw KyberException.skInconsistent
            }
            if tSize + rhoSize != Kyber.K1024.publicKeySize {
                throw KyberException.skInconsistent
            }
        } else {
            throw KyberException.skInconsistent
        }
    }

    /// Creates a SecretKey from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        try self.init(der: Base64.pemDecode(pem, "PRIVATE KEY"))
    }


    // MARK: Stored Properties
    
    /// The raw key bytes
    public let bytes: Bytes
    
    /// The Kyber OID
    public let oid: ASN1ObjectIdentifier

    /// The corresponding public key
    public let publicKey: PublicKey


    // MARK: Computed Properties

    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }

    /// The ASN1 encoding of *self*
    public var asn1: ASN1 { get {
        return ASN1Sequence()
            .add(ASN1.ZERO)
            .add(ASN1Sequence().add(self.oid))
            .add(ASN1OctetString(
                ASN1Sequence()
                    .add(ASN1.ZERO)
                    .add(ASN1OctetString(self.s))
                    .add(ASN1Ctx(0, ASN1Sequence()
                        .add(ASN1OctetString(self.publicKey.t))
                        .add(ASN1OctetString(self.publicKey.rho)).encode()))
                    .add(ASN1OctetString(self.h))
                    .add(ASN1OctetString(self.z)).encode()))
        } }

    /// The DER encoding of *self*
    public var der: Bytes { get { return self.asn1.encode() } }

    /// The PEM base 64 encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.der, "PRIVATE KEY") } }
    
    /// The s part of *self*
    public var s: Bytes { get { return Bytes(self.bytes[0 ..< self.tStart]) } }

    /// The t part of *self*
    public var t: Bytes { get { return Bytes(self.bytes[self.tStart ..< self.rhoStart]) } }

    /// The rho part of *self*
    public var rho: Bytes { get { return Bytes(self.bytes[self.rhoStart ..< self.hStart]) } }

    /// The h part of *self*
    public var h: Bytes { get { return Bytes(self.bytes[self.hStart ..< self.zStart]) } }

    /// The z part of *self*
    public var z: Bytes { get { return Bytes(self.bytes[self.zStart ..< self.bytes.count]) } }
    
    
    // MARK: Methods

    /// Equality
    ///
    /// - Parameters:
    ///   - x: First key
    ///   - y: Second key
    /// - Returns: *true* if x = y, *false* otherwise
    public static func ==(x: SecretKey, y: SecretKey) -> Bool {
        return x.oid == y.oid && x.bytes == y.bytes
    }

    /// The decapsulation function
    ///
    /// - Parameters:
    ///   - ct: The ciphertext
    /// - Returns: The shared secret
    /// - Throws: A *ctSize* exception if *ct* has wrong size
    public func Decapsulate(ct: Bytes) throws -> Bytes {
        guard ct.count == self.kyber.cipherTextSize else {
            throw KyberException.ctSize(value: ct.count, shouldBe: self.kyber.cipherTextSize)
        }
        return self.kyber.CCAKEM_Dec(ct, self)
    }

}
