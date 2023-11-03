//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

///
/// Kyber exceptions
///
public enum KyberException: Error, CustomStringConvertible {
    
    /// Textual description of *self*
    public var description: String {
        switch self {
        case .pkSize(let value):
            return "Wrong public key size \(value), should be 800, 1184 or 1568"
        case .skSize(let value):
            return "Wrong secret key size \(value), should be 1632, 2400 or 3168"
        case .skInconsistent:
            return "Wrong secret key data"
        case .ctSize(let value, let shouldBe):
            return "Wrong cipher text size \(value), should be \(shouldBe)"
        case .base64:
            return "Base64 decoding exception"
        case .pemStructure:
            return "PEM structure is wrong"
        case .asn1Structure:
            return "ASN1 structure is wrong"
        }
    }

    /// Wrong public key size
    case pkSize(value: Int)

    /// Wrong secret key size
    case skSize(value: Int)

    /// Inconsistent secret key data
    case skInconsistent

    /// Wrong cipher text size
    case ctSize(value: Int, shouldBe: Int)
    
    /// Base64 decoding exception
    case base64
    
    /// PEM structure is wrong
    case pemStructure

    /// ASN1 structure is wrong
    case asn1Structure

}
