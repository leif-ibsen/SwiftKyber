//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

/// The Kyber exceptions
public enum KyberException: Error {
    
    /// Wrong encapsulation key size
    case encapsulationKeySize(value: Int)

    /// Inconsistent encapsulation key data
    case encapsulationKeyInconsistent

    /// Wrong decapsulation key size
    case decapsulationKeySize(value: Int)

    /// Inconsistent decapsulation key data
    case decapsulationKeyInconsistent

    /// Wrong cipher text size
    case cipherTextSize(value: Int)
    
}
