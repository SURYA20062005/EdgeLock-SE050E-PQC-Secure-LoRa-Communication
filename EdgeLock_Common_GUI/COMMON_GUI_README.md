# Common Alice/Bob GUI — same files on both Raspberry Pis

Copy this **entire same folder** onto Alice and Bob. No separate Alice/Bob code folders are needed.

## Start
1. On each Raspberry Pi open `RUN_GUI.py` in Thonny using the existing Python environment with `oqs`.
2. Click **Bob** on the Bob Pi and **Alice** on the Alice Pi.
3. Start the PQC session on Bob, then Alice. Follow the same GUI pairing, authentication and messaging workflow.

The existing GUI flow, key management, cryptography, animations and messaging code is retained. The LoRa driver location now comes from the current Pi user's home directory: `~/Documents/SX126X_LoRa_HAT_915/raspberrypi/python`. Ensure the driver is installed there on **both** Pis. The NXP SCP03 bridge must already be compiled on each Pi.

CLI fallback: `python main.py --role Alice` or `python main.py --role Bob`.

Security note: independently compare fingerprints before approving peer trust.

This package has been syntax-checked but has not been tested on physical LoRa/SE050E hardware.
