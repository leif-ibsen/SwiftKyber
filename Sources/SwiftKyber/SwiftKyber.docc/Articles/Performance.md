# Performance

## 

SwiftKyber's key generation, encapsulation and decapsulation performance was measured on a MacBook Pro 2024, Apple M3 chip.

The table below shows the times in microseconds for the three Kyber kinds.

| Kind        | GenerateKeyPair | Encapsulate | Decapsulate |
|:------------|----------------:|------------:|------------:|
| K512        | 91 uSec         | 63 uSec     | 83 uSec     |
| K768        | 140 uSec        | 100 uSec    | 127 uSec    |
| K1024       | 205 uSec        | 146 uSec    | 183 uSec    |
