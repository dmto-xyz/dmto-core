# Blind Signatures

## Symbols

| Symbol          | Meaning          | Code                    |
| --------------- | ---------------- | ----------------------- |
| `x`             | Mint private key | `SecretKey`             |
| `K = x·G`       | Mint public key  | `MintKey.pubkey`        |
| `secret`        | User secret      | `Vec<u8>`               |
| `Y = H(secret)` | Curve point      | `hash_to_curve(secret)` |
| `r`             | Blind factor     | `Scalar`                |
| `G`             | Generator        | implicit                |
| `B_`            | Blinded message  | `blinded_point`         |
| `C'`            | Blind signature  | `blind_sig`             |
| `C`             | Final signature  | `note.c`                |

## Steps

1. User commits to a message

User creates a secret:
```
secret ← random
Y = H(secret)
```

This is the message the mint will sign.

2. User blinds the message

User chooses a random scalar:
```
r ∈ 𝔽ₙ
```

Then computes:
```
B_ = Y + rG
```

**Important:**

- Mint does not know Y
- Mint does not know r
- Mint only sees B_

📌 This hides the message.

3. Mint signs the blinded message

Mint has private key x.
It computes:
```
C' = x · B_
```

Substitute B_:
```
C' = x · (Y + r·G)
```

Distribute scalar multiplication:
```
C' = x·Y + x·r·G
```

But:
```
x·G = K
```

So:
```
C' = x·Y + r·K
```

📌 This is the key insight.
The blind signature is almost what we want, but it has an extra term r·K.

4. User unblinds

User knows:
- r
- K
- C'

So they compute:
```
C = C' − r·K
```

Substitute C':
```
C = (x·Y + r·K) − r·K
```

Cancel terms:
```
C = x·Y
```

🎉 Done
This is exactly what the mint would have produced if it had signed Y directly.

5. mint can verify later

Mint checks:

```
C ?= x · Y
```

Which is exactly what you store in the note:
```
Note {
    secret,
    y: Y,
    c: C,
}
```

## Diagram

```
User:                     Mint:
-----                     -----
Y = H(secret)
r ← random

B_ = Y + rG  ─────────▶  C' = x·B_
                             │
                             │  (blind)
                             ▼
User:
C = C' − rK
  = x·Y
```
