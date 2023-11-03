//
//  Vector.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 10/10/2023.
//

// Vector containing polynomials
struct Vector: Equatable {
    
    var polynomial: [Polynomial]
    let n: Int
    
    init(_ n: Int) {
        self.polynomial = [Polynomial](repeating: Polynomial(), count: n)
        self.n = n
    }
    
    // Number Theoretic Transform
    func NTT() -> Vector {
        var x = Vector(self.n)
        for i in 0 ..< self.n {
            x.polynomial[i] = self.polynomial[i].NTT()
        }
        return x
    }

    // Inverse Number Theoretic Transform
    func INTT() -> Vector {
        var x = Vector(self.n)
        for i in 0 ..< self.n {
            x.polynomial[i] = self.polynomial[i].INTT()
        }
        return x
    }

    // x + y
    static func +(_ x: Vector, _ y: Vector) -> Vector {
        assert(x.n == y.n)
        var sum = Vector(x.n)
        for i in 0 ..< sum.n {
            sum.polynomial[i] = x.polynomial[i] + y.polynomial[i]
        }
        return sum
    }

    // x * y
    static func *(_ x: Vector, _ y: Vector) -> Polynomial {
        assert(x.n == y.n)
        var pol = Polynomial()
        for i in 0 ..< x.n {
            pol += x.polynomial[i] * y.polynomial[i]
        }
        return pol
    }

    func Compress(_ d: Int) -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v.polynomial[i] = self.polynomial[i].Compress(d)
        }
        return v
    }

    func Decompress(_ d: Int) -> Vector {
        var v = Vector(self.n)
        for i in 0 ..< self.n {
            v.polynomial[i] = self.polynomial[i].Decompress(d)
        }
        return v
    }

    func Encode(_ l: Int) -> Bytes {
        var x: Bytes = []
        for i in 0 ..< self.n {
            x += self.polynomial[i].Encode(l)
        }
        return x
    }

    static func Decode(_ x: Bytes, _ l: Int) -> Vector {
        let step = l << 5
        let n = x.count / step
        var v = Vector(n)
        var from = 0
        for i in 0 ..< n {
            v.polynomial[i] = Polynomial(Kyber.Decode(Bytes(x[from ..< from + step])))
            from += step
        }
        return v
    }
}

