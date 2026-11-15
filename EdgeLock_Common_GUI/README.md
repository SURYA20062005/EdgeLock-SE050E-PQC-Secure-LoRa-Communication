# EdgeLock SE050E | Post-Quantum Secure LoRa Communication

**A GUI-based, two-node research prototype for post-quantum authenticated wireless messaging.**

**GUI screenshots:** [Role selection](docs/screenshots/README.md) · Alice GUI · Bob GUI (add actual screenshots to the folder below).

> **Research prototype:** This repository is intended for controlled laboratory evaluation, not production deployment.

## Overview

The same Python application runs on two Raspberry Pi 5 nodes. Select **Alice** on one and **Bob** on the other. The GUI visualizes LoRa TX/RX activity, EdgeLock key provisioning, mutual authentication, key establishment, and bidirectional encrypted messaging.

| Layer | Implementation |
| --- | --- |
| Compute | Raspberry Pi 5 (Alice and Bob) |
| Wireless | Waveshare SX126X LoRa HAT, 915 MHz |
| Secure element | NXP EdgeLock SE050E |
| Host–secure-element channel | Platform SCP03 over I²C |
| Authentication | ML-DSA-65 signatures and out-of-band public-key fingerprint comparison |
| Key establishment | ML-KEM-512 + HKDF-SHA256 |
| Message protection | AES-256-GCM performed via SE050E |
| User interface | Python Tkinter |

## System workflow

```text
Alice Pi 5  <-- authenticated LoRa exchange -->  Bob Pi 5
    |                                            |
 SCP03 over I²C                              SCP03 over I²C
    |                                            |
EdgeLock SE050E                             EdgeLock SE050E
```

1. Both nodes authorize replacement of their lab identity keys, generate fresh ML-DSA-65 key pairs, and provision EdgeLock key objects.
2. Alice and Bob exchange public keys over LoRa and independently compare SHA-256 fingerprints before trusting peer keys.
3. ML-DSA-65 challenge-response establishes mutual proof of possession of the accepted identity private keys.
4. Signed ML-KEM-512 exchange creates a shared secret; HKDF-SHA256 derives a 32-byte session key.
5. The session key is imported into EdgeLock via the SCP03-protected bridge.
6. Either GUI sends encrypted messages; the receiving node decrypts using its EdgeLock secure element.

## Key objects in EdgeLock

| Object ID | Description |
| --- | --- |
| `0x7A050A28` | Own ML-DSA-65 public key (binary object) |
| `0x7A050A29` | Own ML-DSA-65 private key (exportable binary object) |
| `0x7A050A31` | Verified peer ML-DSA-65 public key |
| `0x7A05F041` | AES-256 session key |

**Security scope:** ML-DSA and ML-KEM computations run on the Raspberry Pi using liboqs; the ML-DSA private key is retrieved into host memory for signing. HKDF is performed on the Pi before AES-key import. SCP03 protects the I²C channel, not the LoRa link. Default Platform SCP03 credentials are suitable only for controlled evaluation and should be replaced for deployment. A GUI trust click is meaningful only after independent fingerprint comparison.

## Requirements

- Two Raspberry Pi 5 boards with compatible Waveshare SX126X 915 MHz LoRa HATs and antennas
- One connected NXP EdgeLock SE050E per Raspberry Pi; I²C enabled
- NXP Plug & Trust middleware and compiled Platform SCP03 bridge
- Python with `liboqs` / `liboqs-python` (`oqs`), `pycryptodome`, `pyserial`, and Tkinter
- SX126X driver at `~/Documents/SX126X_LoRa_HAT_915/raspberrypi/python/sx126x.py` on each Pi

`requirements.txt` lists pip-installable Python dependencies; `liboqs-python` and the NXP middleware require separate setup.

## Run on both Raspberry Pis

1. Copy the **same project folder** onto both devices.
2. Open `RUN_GUI.py` in **Thonny**, using the interpreter/environment with `oqs` installed.
3. On the Bob device, select **Bob** and start the session; then select **Alice** on the Alice device and start it.
4. Approve fresh identity replacement only if overwriting reserved objects is intended.
5. Compare each received SHA-256 fingerprint with the other device's independently obtained local fingerprint, then approve pairing.
6. After successful mutual authentication, KEM, and AES key import, exchange messages in the chat window.

**CLI fallback:** `python main.py --role Alice` or `python main.py --role Bob` (terminal workflow differs from GUI).

## Repository layout

```text
EdgeLock_Common_GUI/
├── RUN_GUI.py              # Common entry point
├── gui.py                  # Role selection, flow animations, chat
├── identity.py             # Fresh ML-DSA identity provisioning
├── pairing.py              # Public-key exchange and trust
├── authentication.py       # Signed mutual challenge-response
├── key_exchange.py         # ML-KEM and HKDF session setup
├── messaging.py            # Messaging helpers
├── lora_transport.py       # SX126X radio transport
├── se050_bridge.py         # Python-to-secure-element bridge
├── se050_bridge.c          # NXP Plug & Trust bridge implementation
├── main.py                 # CLI entry point
├── requirements.txt
├── docs/
│   ├── architecture.md
│   ├── security.md
│   └── screenshots/        # Add GUI screenshots here
├── LICENSE_GUIDANCE.md
├── CONTRIBUTING.md
├── SECURITY.md
└── .gitignore
```

## Screenshots and experimental results

Add sanitized screenshots to [`docs/screenshots/`](docs/screenshots/README.md). Include exactly three images: `01-role-selection.png`, `02-alice-gui.png`, and `03-bob-gui.png`. Do not include secret keys or private credentials in screenshots.

For a journal paper, independently record LoRa transfer latency, chunk counts, authentication/KEM times, SCP03 key-import time, AES-GCM times, and negative tests (substituted keys, forged signatures, altered ciphertext, and replay attempts). GUI animations are visual indicators, **not** packet-timing measurements.

## Status and limitations

The supplied implementation has been reported working on the author's two-node hardware setup. This packaging change adds documentation only; it does not alter or independently revalidate the runtime. LoRa is half-duplex, and simultaneous sends may collide. This prototype does not claim production-grade device provisioning or complete replay/collision resistance.

## License and citation

No license is assigned automatically. See [`LICENSE_GUIDANCE.md`](LICENSE_GUIDANCE.md) before selecting one, especially if a publication or institutional policy applies. Add paper DOI and citation metadata after publication.
