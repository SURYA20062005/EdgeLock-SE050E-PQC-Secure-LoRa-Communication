# Cryptographic boundary and trust model

| Component | Operation | Boundary |
| --- | --- | --- |
| Raspberry Pi + liboqs | ML-DSA-65 generation/sign/verify; ML-KEM-512 encapsulation/decapsulation | Host software |
| Raspberry Pi + PyCryptodome | HKDF-SHA256 derivation | Host software |
| EdgeLock SE050E | Persistent key objects; AES-256-GCM encrypt/decrypt | Secure element |
| Platform SCP03 | Protects host–SE050E I²C communication | Local wired channel |
| LoRa | Transfers authenticated handshake and encrypted messages | Wireless transport |

**Trust bootstrap:** The received public key is untrusted until its SHA-256 fingerprint has been compared with a value obtained from the peer through an independent trusted channel. Signature verification then proves possession of the accepted key's private counterpart.

**Cautions:** Default SCP03 credentials are unsuitable for production; private ML-DSA key bytes are read into Pi memory; fresh identities require renewed trust verification; radio collisions and active adversarial conditions need additional testing.
