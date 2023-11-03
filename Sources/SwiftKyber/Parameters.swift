//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import ASN1

struct KyberParameters {
    
    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let oid: ASN1ObjectIdentifier
    
    // Figures from [KYBER] section 1.4

    // Kyber512 parameters
    static let k512 =  KyberParameters(k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, oid: ASN1ObjectIdentifier("1.3.6.1.4.1.25258.1.7.1")!)
    
    // Kyber768 parameters
    static let k768 =  KyberParameters(k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, oid: ASN1ObjectIdentifier("1.3.6.1.4.1.25258.1.7.2")!)
    
    // Kyber1024 parameters
    static let k1024 = KyberParameters(k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, oid: ASN1ObjectIdentifier("1.3.6.1.4.1.25258.1.7.3")!)
     
}
