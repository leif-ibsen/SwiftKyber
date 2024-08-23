//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//


// Parameters for the three Kyber instances
struct KyberParameters {
    
    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let ekSize: Int
    let dkSize: Int
    let ctSize: Int

    // Figures from [FIPS203] section 8

    // K512 parameters
    static let k512 =  KyberParameters(k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, ekSize:  800, dkSize: 1632, ctSize: 768)
    
    // K768 parameters
    static let k768 =  KyberParameters(k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, ekSize: 1184, dkSize: 2400, ctSize: 1088)
    
    // K1024 parameters
    static let k1024 = KyberParameters(k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, ekSize: 1568, dkSize: 3168, ctSize: 1568)
     
}
