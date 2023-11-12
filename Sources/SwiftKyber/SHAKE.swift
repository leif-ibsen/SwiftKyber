//
//  File.swift
//  
//
//  Created by Leif Ibsen on 05/10/2023.
//

class SHAKE256 {
    
    let sha3: SHA3
    
    init() {
        self.sha3 = SHA3_256()
    }

    func update(_ msg: Bytes) {
        self.sha3.update(msg)
    }

    // FIPS202 - algorithm 8
    func digest(_ d: Int) -> Bytes {
        assert(d >= 0)
        var padBytes = Bytes(repeating: 0, count: self.sha3.buffer.count - self.sha3.bytes % self.sha3.buffer.count)
        padBytes[0] = 0x1f
        padBytes[padBytes.count - 1] |= 0x80
        self.update(padBytes)
        
        assert(self.sha3.totalBytes % self.sha3.buffer.count == 0)

        var Z: Bytes = []
        while Z.count < d {
            Z += Bytes(self.sha3.S[0 ..< self.sha3.buffer.count])
            self.sha3.doBuffer()
        }
        self.sha3.reset()
        return Bytes(Z[0 ..< d])
    }

}

// Extendable output function - based on SHAKE128
class XOF {
    
    let sha3: SHA3
    var buffer: Bytes
    var ndx: Int
    
    init(_ seed: Bytes) {
        self.sha3 = SHA3_128()
        self.sha3.update(seed)
        var padBytes = Bytes(repeating: 0, count: self.sha3.buffer.count - self.sha3.bytes % self.sha3.buffer.count)
        padBytes[0] = 0x1f
        padBytes[padBytes.count - 1] |= 0x80
        self.sha3.update(padBytes)
        self.buffer = Bytes(self.sha3.S[0 ..< self.sha3.buffer.count])
        self.ndx = 0
    }
    
    func read(_ x: inout Bytes) {
        for i in 0 ..< x.count {
            if self.ndx == self.buffer.count {
                self.sha3.doBuffer()
                self.buffer = Bytes(self.sha3.S[0 ..< self.buffer.count])
                self.ndx = 0
            }
            x[i] = self.buffer[self.ndx]
            self.ndx += 1
        }
    }
    
}
