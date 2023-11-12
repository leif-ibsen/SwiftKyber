//
//  Kyber.swift
//  SwiftKyberTest
//
//  Created by Leif Ibsen on 09/10/2023.
//

import Foundation
import ASN1

/// Unsigned 8 bit value
public typealias Byte = UInt8
/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

/// The Kyber structure contains three static members *K512*, *K768* and *K1024*
/// corresponding to the three defined Kyber instances. There is no public constructor,
/// so it is not possible to create other instances.
public struct Kyber {
    
    
    // MARK: Kyber instances
    
    /// The Kyber512 instance
    public static let K512 = Kyber(KyberParameters.k512)

    /// The Kyber768 instance
    public static let K768 = Kyber(KyberParameters.k768)

    /// The Kyber1024 instance
    public static let K1024 = Kyber(KyberParameters.k1024)

    
    // MARK: Stored properties

    /// The Kyber OID
    public internal(set) var OID: ASN1ObjectIdentifier!


    // MARK: Methods
    
    /// Generates a public key and a secret key
    ///
    /// - Returns: The public key *pk* and the secret key *sk*
    public func GenerateKeyPair() -> (pk: PublicKey, sk: SecretKey) {
        let (pk, sk) = CCAKEM_KeyGen([])
        do {
            return (try PublicKey(bytes: pk), try SecretKey(bytes: sk))
        } catch {
            // Shouldn't happen
            fatalError("GenerateKeyPair inconsistency")
        }
    }

    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    static let N = 256
    static let N32 = 32
    static let Q = 3329
    static let Q2 = 1665
    static let rhoSize = 32
    static let hSize = 32
    static let zSize = 32

    let k: Int
    let eta1: Int
    let eta2: Int
    let du: Int
    let dv: Int
    let sSize: Int
    let tSize: Int
    let publicKeySize: Int
    let secretKeySize: Int
    let cipherTextSize: Int
    let sha256: SHA3_256
    let sha512: SHA3_512
    let shake256: SHAKE256

    init(_ kp: KyberParameters) {
        self.k = kp.k
        self.eta1 = kp.eta1
        self.eta2 = kp.eta2
        self.du = kp.du
        self.dv = kp.dv
        self.sSize = self.k * 384
        self.tSize = self.k * 384
        self.publicKeySize = self.tSize + Kyber.rhoSize
        self.secretKeySize = self.sSize + self.publicKeySize + Kyber.hSize + Kyber.zSize
        self.cipherTextSize = (self.k * self.du + self.dv) * Kyber.N32
        self.OID = kp.oid
        self.sha256 = SHA3_256()
        self.sha512 = SHA3_512()
        self.shake256 = SHAKE256()
    }
    
    
    // Message digest helper functions
    
    func H(_ seed: Bytes) -> Bytes {
        self.sha256.update(seed)
        return self.sha256.digest()
    }
    
    func G(_ seed: Bytes) -> (Bytes, Bytes) {
        self.sha512.update(seed)
        let x = self.sha512.digest()
        return (Bytes(x[0 ..< 32]), Bytes(x[32 ..< 64]))
    }
    
    func PRF(_ seed: Bytes, _ N: Byte, _ eta: Int) -> Bytes {
        self.shake256.update(seed + [N])
        return self.shake256.digest(eta << 6)
    }

    func KDF(_ seed: Bytes) -> Bytes {
        self.shake256.update(seed)
        return self.shake256.digest(32)
    }
    
    
    // Compression and decompression
    
    func Compress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 < d && d < 12)
        let (q, r) = (x << d).quotientAndRemainder(dividingBy: Kyber.Q)
        return (r >= Kyber.Q2 ? q + 1 : q) & (1 << d - 1)
    }
    
    func Compress(_ p: Polynomial, _ d: Int) -> Polynomial {
        var x = Polynomial()
        for i in 0 ..< Kyber.N {
            x.coefficient[i] = Compress(p.coefficient[i], d)
        }
        return x
    }

    func Compress(_ v: Vector, _ d: Int) -> Vector {
        var x = Vector(v.n)
        for i in 0 ..< v.n {
            x.polynomial[i] = Compress(v.polynomial[i], d)
        }
        return x
    }

    func Decompress(_ x: Int, _ d: Int) -> Int {
        assert(0 <= x && x < Kyber.Q)
        assert(0 < d && d < 12)
        let xQ = (x * Kyber.Q) >> (d - 1)
        return xQ & 1 == 1 ? (xQ >> 1) + 1 : xQ >> 1
    }

    func Decompress(_ p: Polynomial, _ d: Int) -> Polynomial {
        var x = Polynomial()
        for i in 0 ..< Kyber.N {
            x.coefficient[i] = Decompress(p.coefficient[i], d)
        }
        return x
    }

    func Decompress(_ v: Vector, _ d: Int) -> Vector {
        var x = Vector(v.n)
        for i in 0 ..< v.n {
            x.polynomial[i] = Decompress(v.polynomial[i], d)
        }
        return x
    }

    // [KYBER] - Algorithm 1
    func Parse(_ xof: XOF) -> Polynomial {
        var x = [Int](repeating: 0, count: Kyber.N)
        var j = 0
        let bufferSize = 504 // 3 * SHAKE128 buffer size
        var xofBuffer = Bytes(repeating: 0, count: bufferSize)
        var xofIndex = bufferSize
        while j < Kyber.N {
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
                x[j] = d1
                j += 1
            }
            if d2 < Kyber.Q && j < Kyber.N {
                x[j] = d2
                j += 1
            }
        }
        return Polynomial(x)
    }

    // [KYBER] - Algorithm 2
    func CBD(_ x: Bytes, _ eta: Int) -> Polynomial {
        assert(x.count == eta << 6)
        let onebits: [Int] = [0, 1, 1, 2, 1, 2, 2, 3]
        var f = [Int](repeating: 0, count: Kyber.N)
        var a: Int
        var b: Int
        var bitNo = 0
        if eta == 2 {
            for i in 0 ..< Kyber.N {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    a = Int(x[byteNo] & 0x3)
                    b = Int((x[byteNo] >> 2) & 0x3)
                case 4:
                    a = Int((x[byteNo] >> 4) & 0x3)
                    b = Int((x[byteNo] >> 6) & 0x3)
                default:
                    fatalError("CBD")
                }
                bitNo += 4
                f[i] = Kyber.subModQ(onebits[a], onebits[b])
            }
        } else {
            assert(eta == 3)
            for i in 0 ..< Kyber.N {
                let byteNo = bitNo >> 3
                switch bitNo & 0x7 {
                case 0:
                    a = Int(x[byteNo] & 0x7)
                    b = Int((x[byteNo] >> 3) & 0x7)
                case 2:
                    a = Int((x[byteNo] >> 2) & 0x7)
                    b = Int((x[byteNo] >> 5) & 0x7)
                case 4:
                    a = Int((x[byteNo] >> 4) & 0x7)
                    b = Int((x[byteNo] >> 7) & 0x1 | ((x[byteNo + 1] & 0x3) << 1))
                case 6:
                    a = Int((x[byteNo] >> 6) & 0x3 | ((x[byteNo + 1] & 0x1) << 2))
                    b = Int((x[byteNo + 1] >> 1) & 0x7)
                default:
                    fatalError("CBD")
                }
                bitNo += 6
                f[i] = Kyber.subModQ(onebits[a], onebits[b])
            }
        }
        return Polynomial(f)
    }

    // [KYBER] - Algorithm 3
    func Decode(_ bytes: Bytes) -> Polynomial {
        assert(bytes.count & 0x1f == 0)
        let l = bytes.count >> 5
        var x = [Int](repeating: 0, count: Kyber.N)
        var il = 0
        for i in 0 ..< x.count {
            for j in 0 ..< l {
                x[i] |= (Int(bytes[(il + j) >> 3] >> ((il + j) & 0x7)) & 1) << j
            }
            il += l
        }
        return Polynomial(x)
    }

    func Decode(_ x: Bytes, _ l: Int) -> Vector {
        let step = l << 5
        let n = x.count / step
        var v = Vector(n)
        var from = 0
        for i in 0 ..< n {
            v.polynomial[i] = Decode(Bytes(x[from ..< from + step]))
            from += step
        }
        return v
    }

    func Encode(_ pol: Polynomial, _ l: Int) -> Bytes {
        assert(0 < l && l <= 12)
        var x = Bytes(repeating: 0, count: l << 5)
        var il = 0
        for i in 0 ..< Kyber.N {
            for j in 0 ..< l {
                let bit = pol.coefficient[i] & (1 << j) != 0 ? Byte(1) : Byte(0)
                x[(il + j) >> 3] |= bit << ((il + j) & 0x7)
            }
            il += l
        }
        return x
    }

    func Encode(_ vec: Vector, _ l: Int) -> Bytes {
        assert(0 < l && l <= 12)
        var x: Bytes = []
        for i in 0 ..< vec.n {
            x += Encode(vec.polynomial[i], l)
        }
        return x
    }

    // [KYBER] - Algorithm 4
    func CPAPKE_KeyGen(_ seed: Bytes = []) -> (pk: Bytes, sk: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        var d = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&d)
        } else {
            d = seed
        }
        let (rho, sigma) = G(d)
        var N = Byte(0)
        var Ahat = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                Ahat.vector[i].polynomial[j] = Parse(XOF(rho + [Byte(j), Byte(i)]))
            }
        }
        var s = Vector(self.k)
        for i in 0 ..< self.k {
            s.polynomial[i] = CBD(PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        var e = Vector(self.k)
        for i in 0 ..< self.k {
            e.polynomial[i] = CBD(PRF(sigma, N, self.eta1), self.eta1)
            N += 1
        }
        let sHat = s.NTT()
        let eHat = e.NTT()
        let tHat = Ahat * sHat + eHat
        let pk = Encode(tHat, 12) + rho
        let sk = Encode(sHat, 12)
        return (pk, sk)
    }
    
    //  [KYBER] - Algorithm 5
    func CPAPKE_Enc(_ pk: Bytes, _ m: Bytes, _ coins: Bytes) -> Bytes {
        assert(pk.count == 12 * self.k * Kyber.N32 + 32)
        assert(m.count == 32)
        assert(coins.count == 32)
        var N = Byte(0)
        let tHat = Decode(pk, 12)
        let rho = Bytes(pk[pk.count - Kyber.rhoSize ..< pk.count])
        var AhatT = Matrix(self.k)
        for i in 0 ..< self.k {
            for j in 0 ..< self.k {
                AhatT.vector[i].polynomial[j] = Parse(XOF(rho + [Byte(i), Byte(j)]))
            }
        }
        var r = Vector(self.k)
        for i in 0 ..< self.k {
            r.polynomial[i] = CBD(PRF(coins, N, self.eta1), self.eta1)
            N += 1
        }
        var e1 = Vector(self.k)
        for i in 0 ..< self.k {
            e1.polynomial[i] = CBD(PRF(coins, N, self.eta2), self.eta2)
            N += 1
        }
        let e2 = CBD(PRF(coins, N, self.eta2), self.eta2)
        let rHat = r.NTT()
        let u = (AhatT * rHat).INTT() + e1
        let v = (tHat * rHat).INTT() + e2 + Decompress(Decode(m), 1)
        let c1 = Encode(Compress(u, self.du), self.du)
        let c2 = Encode(Compress(v, self.dv), self.dv)
        return c1 + c2
    }

    //  [KYBER] - Algorithm 6
    func CPAPKE_Dec(_ sk: Bytes, _ ct: Bytes) -> Bytes {
        assert(sk.count == 12 * self.k * Kyber.N32)
        assert(ct.count == (self.du * self.k + self.dv) * Kyber.N32)
        let index = self.du * self.k * Kyber.N32
        let u = Decompress(Decode(Bytes(ct[0 ..< index]), self.du), self.du)
        let v = Decompress(Decode(Bytes(ct[index ..< ct.count])), self.dv)
        let sHat = Decode(sk, 12)
        return Encode(Compress(v - (sHat * u.NTT()).INTT(), 1), 1)
    }

    // [KYBER] - Algorithm 7
    func CCAKEM_KeyGen(_ seed: Bytes) -> (pk: Bytes, sk: Bytes) {
        assert(seed.count == 0 || seed.count == 64)
        var z = Bytes(repeating: 0, count: 32)
        var s1: Bytes
        if seed.count == 0 {
            s1 = []
            Kyber.randomBytes(&z)
        } else {
            s1 = Bytes(seed[0 ..< 32])
            z = Bytes(seed[32 ..< 64])
        }
        let (pk, sk) = CPAPKE_KeyGen(s1)
        return (pk, sk + pk + H(pk) + z)
    }
    
    // [KYBER] - Algorithm 8
    func CCAKEM_Enc(_ pk: PublicKey, _ seed: Bytes) -> (ct: Bytes, K: Bytes) {
        assert(seed.count == 0 || seed.count == 32)
        var m = Bytes(repeating: 0, count: 32)
        if seed.count == 0 {
            Kyber.randomBytes(&m)
        } else {
            m = seed
        }
        m = H(m)
        let (_K, r) = G(m + H(pk.bytes))
        let ct = CPAPKE_Enc(pk.bytes, m, r)
        let K = KDF(_K + H(ct))
        return (ct, K)
    }

    // [KYBER] - Algorithm 9
    func CCAKEM_Dec(_ ct: Bytes, _ sk: SecretKey) -> Bytes {
        let m = CPAPKE_Dec(sk.s, ct)
        let (K, r) = G(m + sk.h)
        let _ct = CPAPKE_Enc(sk.t + sk.rho, m, r)
        return Equal(ct, _ct) ? KDF(K + H(ct)) : KDF(sk.z + H(ct))
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
    
    // Multiplication modulo Kyber.Q using Barrett reduction
    static func mulModQ(_ a: Int, _ b: Int) -> Int {
        assert(0 <= a && a < Kyber.Q)
        assert(0 <= b && b < Kyber.Q)
        let x = a * b
        let t = x - ((x * bq) >> 32) * Kyber.Q
        return t < Kyber.Q ? t : t - Kyber.Q
    }

}
