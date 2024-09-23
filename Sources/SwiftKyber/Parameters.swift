//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import ASN1

// Parameters for the three Kyber instances
struct Parameters {
    
    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let ekSize: Int
    let dkSize: Int
    let ctSize: Int
    let oid: ASN1ObjectIdentifier

    // Figures from [FIPS203] section 8

    static let params: [Parameters] = [
        // K512 parameters
        Parameters(k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, ekSize:  800, dkSize: 1632, ctSize: 768, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.1")!),
        // K768 parameters
        Parameters(k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, ekSize: 1184, dkSize: 2400, ctSize: 1088, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.2")!),
        // K1024 parameters
        Parameters(k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, ekSize: 1568, dkSize: 3168, ctSize: 1568, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.4.3")!)
        ]
    
    static func paramsFromKind(_ kind: Kind) -> Parameters {
        return params[kind.rawValue]
    }
    
    static func kindFromOID(_ oid: ASN1ObjectIdentifier) -> Kind? {
        for kind in Kind.allCases {
            if paramsFromKind(kind).oid == oid {
                return kind
            }
        }
        return nil
    }

}
