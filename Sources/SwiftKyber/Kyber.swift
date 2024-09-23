//
//  Kyber.swift
//  SwiftKyber
//
//  Created by Leif Ibsen on 09/10/2023.
//

import Foundation
import ASN1
import Digest

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

public struct Kyber {
    

    // MARK: Static Methods

    /// Generates an encapsulation key and a decapsulation key
    ///
    /// - Parameters:
    ///   - kind: The Kyber kind
    /// - Returns: The encapsulation key `encap` and the decapsulation key `decap`
    public static func GenerateKeyPair(kind: Kind) -> (encap: EncapsulationKey, decap: DecapsulationKey) {
        do {
            let kyber = Kyber(kind)
            let (encap, decap) = kyber.ML_KEMKeyGen()
            return (try EncapsulationKey(encap, kyber), try DecapsulationKey(decap, kyber))
        } catch {
            // Shouldn't happen
            fatalError("GenerateKeyPair inconsistency")
        }
    }

    static func randomBytes(_ n: Int) -> Bytes {
        var bytes = Bytes(repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &bytes) == errSecSuccess else {
            fatalError("SecRandomCopyBytes failed")
        }
        return bytes
    }

    static let Q = 3329
    static let rhoSize = 32
    static let hSize = 32
    static let zSize = 32
    static let sha256 = MessageDigest(.SHA3_256)
    static let sha512 = MessageDigest(.SHA3_512)
    static let shake256 = SHAKE(.SHAKE256)

    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let ekSize: Int
    let dkSize: Int
    let ctSize: Int
    let oid: ASN1ObjectIdentifier
    let kx384: Int
    let kx768: Int

    init(_ kind: Kind) {
        let param = Parameters.paramsFromKind(kind)
        self.k = param.k
        self.eta1 = param.eta1
        self.eta2 = param.eta2
        self.du = param.du
        self.dv = param.dv
        self.ekSize = param.ekSize
        self.dkSize = param.dkSize
        self.ctSize = param.ctSize
        self.oid = param.oid
        self.kx384 = self.k * 384
        self.kx768 = self.k * 768
    }
    
    
    // Message digest helper functions

    static func G(_ seed: Bytes) -> (Bytes, Bytes) {
        Kyber.sha512.update(seed)
        let x = Kyber.sha512.digest()
        return (Bytes(x[0 ..< 32]), Bytes(x[32 ..< 64]))
    }
    
    static func H(_ seed: Bytes) -> Bytes {
        Kyber.sha256.update(seed)
        return Kyber.sha256.digest()
    }
    
    static func J(_ seed: Bytes) -> Bytes {
        Kyber.shake256.update(seed)
        return Kyber.shake256.digest(32)
    }

    static func PRF(_ seed: Bytes, _ N: Byte, _ eta: Int) -> Bytes {
        assert(seed.count == 32)
        Kyber.shake256.update(seed + [N])
        return Kyber.shake256.digest(eta << 6)
    }

    
    // Compression and decompression
    
    static func Compress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 < d && d < 12)
        let (q, r) = (x << d).quotientAndRemainder(dividingBy: Kyber.Q)
        return (r >= 1665 ? q + 1 : q) & (1 << d - 1)
    }
    
    static func Decompress(_ y: Int, _ d: Int) -> Int {
        assert(0 <= y && y < 1 << d)
        assert(0 < d && d < 12)
        let yQ = (y * Kyber.Q) >> (d - 1)
        return yQ & 1 == 1 ? (yQ >> 1) + 1 : yQ >> 1
    }

    // [FIPS203] - Algorithm 5
    static func ByteEncode(_ F: [Int], _ d: Int) -> Bytes {
        assert(0 < d && d <= 12)
        assert(F.count == 256)
        var x = Bytes(repeating: 0, count: d << 5)
        var id = 0
        for i in 0 ..< 256 {
            for j in 0 ..< d {
                let bit = F[i] & (1 << j) != 0 ? Byte(1) : Byte(0)
                x[(id + j) >> 3] |= bit << ((id + j) & 0x7)
            }
            id += d
        }
        return x
    }

    // [FIPS203] - Algorithm 6
    static func ByteDecode(_ B: Bytes, _ d: Int) -> [Int] {
        assert(0 < d && d <= 12)
        assert(B.count == d * 32)
        var F = [Int](repeating: 0, count: 256)
        var id = 0
        for i in 0 ..< 256 {
            for j in 0 ..< d {
                F[i] |= (Int(B[(id + j) >> 3] >> ((id + j) & 0x7)) & 1) << j
            }
            id += d
        }
        if d == 12 {
            for i in 0 ..< 256 {
                F[i] = Kyber.reduceModQ(F[i])
            }
        }
        return F
    }

    // [FIPS203] - Algorithm 7
    static func SampleNTT(_ B: Bytes) -> Polynomial {
        assert(B.count == 34)
        let xof = XOF(.XOF128, B)
        var a = [Int](repeating: 0, count: 256)
        var j = 0
        let bufferSize = 504 // 3 * SHAKE128 buffer size
        var xofBuffer = Bytes(repeating: 0, count: bufferSize)
        var xofIndex = bufferSize
        while j < 256 {
            if xofIndex == bufferSize {
                xof.read(&xofBuffer)
                xofIndex = 0
            }
            let b0 = Int(xofBuffer[xofIndex])
            let b1 = Int(xofBuffer[xofIndex + 1])
            let b2 = Int(xofBuffer[xofIndex + 2])
            xofIndex += 3
            let d1 = b0 + (b1 & 0xf) << 8
            let d2 = b1 >> 4 + b2 << 4
            if d1 < Kyber.Q {
                a[j] = d1
                j += 1
            }
            if d2 < Kyber.Q && j < 256 {
                a[j] = d2
                j += 1
            }
        }
        return Polynomial(a)
    }

    // [FIPS203] - Algorithm 8
    static func SamplePolyCBD(_ B: Bytes, _ eta: Int) -> Polynomial {
        assert(B.count == eta * 64)
        let onebits: [Int] = [0, 1, 1, 2, 1, 2, 2, 3]
        var f = [Int](repeating: 0, count: 256)
        var x: Byte
        var y: Byte
        var bitNo = 0
        if eta == 2 {
            for i in 0 ..< 256 {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    x = B[byteNo] & 0x3
                    y = (B[byteNo] >> 2) & 0x3
                case 4:
                    x = (B[byteNo] >> 4) & 0x3
                    y = (B[byteNo] >> 6) & 0x3
                default:
                    fatalError("SamplePolyCBD inconsistency")
                }
                bitNo += 4
                f[i] = Kyber.subModQ(onebits[Int(x)], onebits[Int(y)])
            }
        } else {
            assert(eta == 3)
            for i in 0 ..< 256 {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    x = B[byteNo] & 0x7
                    y = (B[byteNo] >> 3) & 0x7
                case 2:
                    x = (B[byteNo] >> 2) & 0x7
                    y = (B[byteNo] >> 5) & 0x7
                case 4:
                    x = (B[byteNo] >> 4) & 0x7
                    y = (B[byteNo] >> 7) & 0x1 | ((B[byteNo + 1] & 0x3) << 1)
                case 6:
                    x = (B[byteNo] >> 6) & 0x3 | ((B[byteNo + 1] & 0x1) << 2)
                    y = (B[byteNo + 1] >> 1) & 0x7
                default:
                    fatalError("SamplePolyCBD inconsistency")
                }
                bitNo += 6
                f[i] = Kyber.subModQ(onebits[Int(x)], onebits[Int(y)])
            }
        }
        return Polynomial(f)
    }

    // [FIPS203] - Algorithm 13
    func K_PKEKeyGen(_ d: Bytes) -> (ekPKE: Bytes, dkPKE: Bytes) {
        assert(d.count == 32)
        let (rho, sigma) = Kyber.G(d + [Byte(self.k)])
        var N = Byte(0)
        var Ahat = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                Ahat.vectors[i].polynomials[j] = Kyber.SampleNTT(rho + [Byte(j), Byte(i)])
            }
        }
        var s = Vector(self.k)
        for i in 0 ..< self.k {
            s.polynomials[i] = Kyber.SamplePolyCBD(Kyber.PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        var e = Vector(self.k)
        for i in 0 ..< self.k {
            e.polynomials[i] = Kyber.SamplePolyCBD(Kyber.PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        let sHat = s.NTT()
        let eHat = e.NTT()
        let tHat = Ahat * sHat + eHat
        let ekPKE = tHat.ByteEncode(12) + rho
        let dkPKE = sHat.ByteEncode(12)
        return (ekPKE, dkPKE)
    }
    
    //  [FIPS203] - Algorithm 14
    func K_PKEEncrypt(_ ekPKE: Bytes, _ m: Bytes, _ r: Bytes) -> Bytes {
        assert(ekPKE.count == self.kx384 + 32)
        assert(m.count == 32)
        assert(r.count == 32)
        var N = Byte(0)
        let tHat = Vector.ByteDecode(ekPKE, 12)
        let rho = ekPKE[self.kx384 ..< self.kx384 + 32]
        var Ahat = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                Ahat.vectors[i].polynomials[j] = Kyber.SampleNTT(rho + [Byte(j), Byte(i)])
            }
        }
        var y = Vector(self.k)
        for i in 0 ..< self.k {
            y.polynomials[i] = Kyber.SamplePolyCBD(Kyber.PRF(r, N, self.eta1), self.eta1)
            N += 1
        }
        var e1 = Vector(self.k)
        for i in 0 ..< self.k {
            e1.polynomials[i] = Kyber.SamplePolyCBD(Kyber.PRF(r, N, self.eta2), self.eta2)
            N += 1
        }
        let e2 = Kyber.SamplePolyCBD(Kyber.PRF(r, N, self.eta2), self.eta2)
        let yHat = y.NTT()
        Ahat.transpose()
        let u = (Ahat * yHat).INTT() + e1
        let my = Polynomial.ByteDecode(m, 1).Decompress(1)
        let v = (tHat * yHat).INTT() + e2 + my
        let c1 = u.Compress(self.du).ByteEncode(self.du)
        let c2 = v.Compress(self.dv).ByteEncode(self.dv)
        return c1 + c2
    }

    //  [FIPS203] - Algorithm 15
    func K_PKEDecrypt(_ dkPKE: Bytes, _ c: Bytes) -> Bytes {
        assert(dkPKE.count == self.kx384)
        assert(c.count == (self.du * self.k + self.dv) * 32)
        let c1 = Bytes(c[0 ..< self.du * self.k << 5])
        let c2 = Bytes(c[self.du * self.k << 5 ..< (self.du * self.k + self.dv) << 5])
        let u = Vector.ByteDecode(c1, self.du).Decompress(self.du)
        let v = Polynomial.ByteDecode(c2, self.dv).Decompress(self.dv)
        let sHat = Vector.ByteDecode(dkPKE, 12)
        let w = v - (sHat * u.NTT()).INTT()
        return w.Compress(1).ByteEncode(1)
    }

    // [FIPS203] - Algorithm 16
    func ML_KEMKeyGen_internal(_ d: Bytes, _ z: Bytes) -> (Bytes, Bytes) {
        assert(d.count == 32)
        assert(z.count == 32)
        let (ek, dk) = K_PKEKeyGen(d)
        return (ek, dk + ek + Kyber.H(ek) + z)
    }

    // [FIPS203] - Algorithm 17
    func ML_KEMEncaps_internal(_ ek: Bytes, _ m: Bytes) -> (Bytes, Bytes) {
        assert(ek.count == self.kx384 + 32)
        assert(m.count == 32)
        let (K, r) = Kyber.G(m + Kyber.H(ek))
        return (K, K_PKEEncrypt(ek, m, r))
    }

    // [FIPS203] - Algorithm 18
    func ML_KEMDecaps_internal(_ dk: Bytes, _ c: Bytes) -> Bytes {
        assert(dk.count == kx768 + 96)
        assert(c.count == (self.du * self.k + self.dv) * 32)
        let dkPKE = dk[0 ..< self.kx384]
        let ekPKE = dk[self.kx384 ..< self.kx768 + 32]
        let h = dk[self.kx768 + 32 ..< self.kx768 + 64]
        let z = dk[self.kx768 + 64 ..< self.kx768 + 96]
        let m1 = K_PKEDecrypt(Bytes(dkPKE), c)
        let (K1, r1) = Kyber.G(m1 + h)
        let K = Kyber.J(z + c)
        let c1 = K_PKEEncrypt(Bytes(ekPKE), m1, r1)
        return Equal(c, c1) ? K1 : K
    }

    // [FIPS203] - Algorithm 19
    func ML_KEMKeyGen() -> (K: Bytes, c: Bytes) {
        let d = Kyber.randomBytes(32)
        let z = Kyber.randomBytes(32)
        return ML_KEMKeyGen_internal(d, z)
    }

    // [FIPS203] - Algorithm 20
    func ML_KEMEncaps(_ ek: Bytes) -> (K: Bytes, ct: Bytes) {
        let m = Kyber.randomBytes(32)
        return ML_KEMEncaps_internal(ek, m)
    }

    // [FIPS203] - Algorithm 21
    func ML_KEMDecaps(_ dk: Bytes, _ c: Bytes) -> Bytes {
        return ML_KEMDecaps_internal(dk, c)
    }

    // Constant-time comparison of c1 and c2
    func Equal(_ c1: Bytes, _ c2: Bytes) -> Bool {
        assert(c1.count == c2.count)
        var equal = true
        for i in 0 ..< c1.count {
            equal = equal && (c1[i] == c2[i])
        }
        return equal
    }
 
    
    // Arithmetic modulo Kyber.Q
    
    // Addition modulo Kyber.Q
    static func addModQ(_ a: Int, _ b: Int) -> Int {
        assert(0 <= a && a < Kyber.Q)
        assert(0 <= b && b < Kyber.Q)
        let x = a + b
        return x < Kyber.Q ? x : x - Kyber.Q
    }
    
    // Subtraction modulo Kyber.Q
    static func subModQ(_ a: Int, _ b: Int) -> Int {
        assert(0 <= a && a < Kyber.Q)
        assert(0 <= b && b < Kyber.Q)
        let x = a - b
        return x < 0 ? x + Kyber.Q : x
    }
    
    // Barrett reduction stuff
    static let bq = (1 << 32) / Kyber.Q

    // Reduce modulo Kyber.Q using Barrett reduction
    static func reduceModQ(_ x: Int) -> Int {
        assert(0 <= x && x < Kyber.Q * Kyber.Q)
        let t = x - ((x * bq) >> 32) * Kyber.Q
        return t < Kyber.Q ? t : t - Kyber.Q
    }

}
