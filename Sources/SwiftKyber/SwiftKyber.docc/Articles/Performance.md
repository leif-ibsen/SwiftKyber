# Performance

## 

SwiftKyber's key generation, encapsulation and decapsulation performance was measured on a MacBook Pro 2024, Apple M3 chip.

The table below shows the times in microseconds for the three Kyber kinds.

| Kind        | GenerateKeyPair | Encapsulate | Decapsulate |
|:------------|----------------:|------------:|------------:|
| K512        | 130 uSec        | 95 uSec     | 110 uSec    |
| K768        | 200 uSec        | 150 uSec    | 180 uSec    |
| K1024       | 300 uSec        | 230 uSec    | 260 uSec    |
