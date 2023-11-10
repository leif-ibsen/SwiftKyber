//
//  Vector.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 10/10/2023.
//

// Vector of polynomials
struct Vector: Equatable {
    
    var polynomial: [Polynomial]
    let n: Int
    
    init(_ n: Int) {
        self.polynomial = [Polynomial](repeating: Polynomial(), count: n)
        self.n = n
    }
    
    // Number Theoretic Transform
    func NTT() -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v.polynomial[i] = self.polynomial[i].NTT()
        }
        return v
    }

    // Inverse Number Theoretic Transform
    func INTT() -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v.polynomial[i] = self.polynomial[i].INTT()
        }
        return v
    }

    // v1 + v2
    static func +(_ v1: Vector, _ v2: Vector) -> Vector {
        assert(v1.n == v2.n)
        var sum = Vector(v1.n)
        for i in 0 ..< sum.n {
            sum.polynomial[i] = v1.polynomial[i] + v2.polynomial[i]
        }
        return sum
    }

    // v1 o v2
    static func *(_ v1: Vector, _ v2: Vector) -> Polynomial {
        assert(v1.n == v2.n)
        var pol = Polynomial()
        for i in 0 ..< v1.n {
            pol += v1.polynomial[i] * v2.polynomial[i]
        }
        return pol
    }

}

