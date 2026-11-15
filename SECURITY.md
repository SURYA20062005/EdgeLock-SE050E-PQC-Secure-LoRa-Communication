# Security policy and research limitations

This is an experimental research prototype, not a production-ready secure messenger.

- **Peer trust:** Verify public-key fingerprints using an independent trusted channel. Clicking a confirmation button without comparison does not authenticate a peer.
- **ML-DSA keys:** The SE050E stores ML-DSA keys as binary objects. The private key is exportable to Raspberry Pi memory for software signing. Do not claim non-exportable hardware-backed PQ signatures.
- **ML-KEM:** Key establishment is computed in host software; the derived AES session key is subsequently imported into EdgeLock.
- **SCP03:** Protects Pi-to-SE050E I²C traffic, not radio frames. Default Platform SCP03 credentials should be replaced by securely provisioned device-specific credentials before any deployment.
- **LoRa:** Simultaneous transmissions may collide. Additional evaluation is needed for replay, denial-of-service, and robust retransmission behavior.
- **Key replacement:** Fresh-identity provisioning overwrites reserved secure-element objects; do not run against objects containing valuable credentials.

Never commit real private keys, credentials, session secrets, or logs that disclose them. For a security issue, contact the repository maintainer privately rather than posting sensitive exploit details in a public issue.
