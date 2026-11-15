# Architecture and protocol flow

```text
Alice Pi 5                              Bob Pi 5
   |                                        |
   |-- ML-DSA-65 public key (LoRa) ------->|
   |<------ ML-DSA-65 public key (LoRa) ---|
   |   OOB SHA-256 fingerprint check       |
   |<------ challenge / signed data ------>|
   |      ML-DSA-65 mutual verification    |
   |-- signed ML-KEM-512 public key ------>|
   |<------ signed ML-KEM ciphertext ------|
   |    shared secret -> HKDF-SHA256       |
   |    AES-256 key -> SE050E via SCP03    |
   |<==== AES-256-GCM encrypted chat ====>|
```

Each Pi connects to its local EdgeLock SE050E via I²C secured using Platform SCP03. The two secure elements do not directly communicate with each other. LoRa transports public-key, authentication, KEM, and encrypted messaging data.

The same `RUN_GUI.py` starts the role-selection interface on either device. See the main README for setup and the precise security boundary.
