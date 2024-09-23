//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

/// The Kyber exceptions
public enum Exception: Error {
    
    /// Wrong ASN1 structure
    case asn1Structure
    
    /// Wrong cipher text size
    case cipherTextSize(value: Int)

    /// Inconsistent encapsulation key data
    case encapsulationKeyInconsistent
    
    /// Wrong encapsulation key size
    case encapsulationKeySize(value: Int)

    /// Inconsistent decapsulation key data
    case decapsulationKeyInconsistent

    /// Wrong decapsulation key size
    case decapsulationKeySize(value: Int)
    
    /// Wrong PEM structure
    case pemStructure
    
}
