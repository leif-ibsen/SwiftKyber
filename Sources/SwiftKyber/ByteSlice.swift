//
//  ByteSlice.swift
//  Slice
//
//  Created by Leif Ibsen on 09/12/2023.
//

struct ByteSlice: CustomStringConvertible {
    
    var array: Bytes
    var from: Int
    let size: Int
    
    init(_ array: Bytes, _ from: Int, _ size: Int) {
        assert(from + size <= array.count)
        self.array = array
        self.from = from
        self.size = size
    }
    
    var description: String {
        return self.bytes.description
    }
    
    var bytes: Bytes {
        return Bytes(self.array[self.from ..< self.from + self.size])
    }

    var count: Int {
        return self.size
    }

    subscript(n: Int) -> Byte {
        get {
            return self.array[self.from + n]
        } set {
            self.array[self.from + n] = newValue
        }
    }

    mutating func next() {
        self.from += self.size
        assert(self.from <= self.array.count)
    }
    
    static func +(_ b1: ByteSlice, _ b2: ByteSlice) -> Bytes {
        return b1.bytes + b2.bytes
    }

    static func +(_ b1: Bytes, _ b2: ByteSlice) -> Bytes {
        return b1 + b2.bytes
    }

    static func +(_ b1: ByteSlice, _ b2: Bytes) -> Bytes {
        return b1.bytes + b2
    }

}

extension Array where Element == Byte {
 
    func slice(_ from: Int, _ size: Int) -> ByteSlice {
        return ByteSlice(self, from, size)
    }
}
