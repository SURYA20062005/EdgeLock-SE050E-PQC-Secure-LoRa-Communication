import os
import sys
import time
import struct
import secrets
import hashlib

import oqs

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


# ============================================================
# ALICE CONFIGURATION
# ============================================================

# Role selected in the shared GUI before this module is imported.
# Both Pis run exactly the same file; use the active user's home directory.
from pathlib import Path
DRIVER_PATH = str(Path.home() / "Documents/SX126X_LoRa_HAT_915/raspberrypi/python")

if DRIVER_PATH not in sys.path:
    sys.path.insert(0, DRIVER_PATH)

import sx126x


FREQ = 915
ADDR = 0
POWER = 22
RSSI = True
AIR_SPEED = 2400
RELAY = False

FREQ_OFFSET = 65

CHUNK_SIZE = 220
MAX_RETRIES = 5
ACK_TIMEOUT = 5


# ============================================================
# PROTOCOL CONSTANTS
# ============================================================

PROTOCOL = b"PI5-LORA-915"

PROTOCOL_VERSION = 1

KEM_NAME = "ML-KEM-512"
SIG_NAME = "ML-DSA-65"

AES_CONTEXT = b"PI5-LoRa-915-MLKEM512-AES256GCM"

MAX_PLAINTEXT = 50000  # JSON envelope limit for text and small files
MAX_FILE_BYTES = 32 * 1024  # Keep LoRa demo transfers manageable


PROGRESS_CALLBACK = None  # GUI-only progress hook; no effect on radio protocol

def _progress(kind, index, total):
    if PROGRESS_CALLBACK is not None:
        try: PROGRESS_CALLBACK(kind, index, total)
        except Exception: pass

# ============================================================
# LORA NODE
# ============================================================

print()
print("============================================================")
print("LoRa - 915 MHz (shared Alice/Bob transport)")
print("============================================================")

node = sx126x.sx126x(
    serial_num="/dev/ttyAMA0",
    freq=FREQ,
    addr=ADDR,
    power=POWER,
    rssi=RSSI,
    air_speed=AIR_SPEED,
    relay=RELAY
)


LORA_HEADER = bytes([
    (ADDR >> 8) & 255,
    ADDR & 255,
    FREQ_OFFSET,
    (ADDR >> 8) & 255,
    ADDR & 255,
    FREQ_OFFSET
])


# ============================================================
# SEND ONE CHUNK
# ============================================================

def send_chunk(data, message_id, index, total):

    packet = (
        LORA_HEADER
        + struct.pack(">IHH",
                      message_id,
                      index,
                      total)
        + data
    )

    for attempt in range(1, MAX_RETRIES + 1):

        print(
            f"Sending chunk {index + 1}/{total}, "
            f"attempt {attempt}"
        )

        node.send(packet)

        start = time.time()

        while time.time() - start < ACK_TIMEOUT:

            if node.ser.inWaiting() >= 13:

                raw = node.ser.read(13)

                if len(raw) != 13:
                    continue

                if raw[3:6] != b"ACK":
                    continue

                mid = struct.unpack(
                    ">I",
                    raw[6:10]
                )[0]

                idx = struct.unpack(
                    ">H",
                    raw[10:12]
                )[0]

                if mid == message_id and idx == index:

                    print("ACK received")
                    return True

            time.sleep(0.05)

        print("ACK timeout")

    return False


# ============================================================
# SEND COMPLETE MESSAGE
# ============================================================

def send_complete(data, message_id=None):

    if message_id is None:
        message_id = secrets.randbits(32)

    chunks = [
        data[i:i + CHUNK_SIZE]
        for i in range(0, len(data), CHUNK_SIZE)
    ]

    total = len(chunks)

    print()
    print(
        f"Sending complete message: "
        f"{len(data)} bytes, {total} chunks"
    )

    for index, chunk in enumerate(chunks):

        ok = send_chunk(
            chunk,
            message_id,
            index,
            total
        )

        if not ok:
            raise RuntimeError(
                f"Transmission failed at chunk "
                f"{index + 1}/{total}"
            )

        _progress('tx', index + 1, total)

    return message_id


# ============================================================
# ============================================================
# VARIABLE-LENGTH APPLICATION PACKET FRAMING
# ============================================================
def send_framed_complete(data):
    """Prefix a byte count and pad to full chunks so the receiver can read safely."""
    framed = struct.pack(">I", len(data)) + data
    padding = (-len(framed)) % CHUNK_SIZE
    if padding:
        framed += b"\x00" * padding
    send_complete(framed)

def unframe_complete(framed):
    if len(framed) < 4:
        raise RuntimeError("Application frame is too short")
    actual_length = struct.unpack(">I", framed[:4])[0]
    if actual_length > MAX_PLAINTEXT + 64:
        raise RuntimeError("Application frame length exceeds configured limit")
    if actual_length > len(framed) - 4:
        raise RuntimeError("Application frame is truncated")
    return framed[4:4 + actual_length]


# RECEIVE COMPLETE MESSAGE
# ============================================================

def receive_complete(expected_size, idle_timeout=None):

    chunks = {}
    idle_deadline = time.monotonic() + idle_timeout if idle_timeout is not None else None

    message_id_expected = None
    total_expected = None

    while True:

        # ----------------------------------------------------
        # WAIT FOR WAVESHARE HEADER + CUSTOM HEADER
        # ----------------------------------------------------

        while node.ser.inWaiting() < 11:
            if idle_deadline is not None and time.monotonic() >= idle_deadline:
                return None
            time.sleep(0.01)

        header = node.ser.read(11)

        if len(header) != 11:
            continue

        message_id, index, total = struct.unpack(
            ">IHH",
            header[3:11]
        )

        # ----------------------------------------------------
        # FIRST CHUNK DEFINES MESSAGE
        # ----------------------------------------------------

        if total < 1 or total > 256 or index >= total:
            raise RuntimeError("Invalid LoRa chunk header")

        if message_id_expected is None:

            message_id_expected = message_id
            total_expected = total

        if message_id != message_id_expected:
            continue

        if total != total_expected:
            continue

        # ----------------------------------------------------
        # CALCULATE EXACT CHUNK SIZE
        # ----------------------------------------------------

        if expected_size is None:
            # Dynamic application packet: sender pads every LoRa chunk to CHUNK_SIZE.
            size = CHUNK_SIZE
        elif index < total - 1:
            size = CHUNK_SIZE
        else:
            size = expected_size - CHUNK_SIZE * (total - 1)

        if size <= 0 or size > CHUNK_SIZE:
            raise RuntimeError(
                f"Invalid final chunk size: {size}"
            )

        # ----------------------------------------------------
        # WAIT FOR DATA + RSSI
        # ----------------------------------------------------

        while node.ser.inWaiting() < size + 1:
            time.sleep(0.01)

        raw = node.ser.read(size + 1)

        if len(raw) != size + 1:
            continue

        chunk_data = raw[:-1]
        rssi = raw[-1]

        chunks[index] = chunk_data
        _progress('rx', len(chunks), total)

        print(
            f"Received chunk {index + 1}/{total}, "
            f"{size} bytes, RSSI {rssi}"
        )

        # ----------------------------------------------------
        # SEND ACK
        # ----------------------------------------------------

        ack = (
            b"ACK"
            + struct.pack(
                ">IH",
                message_id,
                index
            )
        )

        ack_header = bytes([
            0,
            0,
            FREQ_OFFSET,
            (node.addr >> 8) & 255,
            node.addr & 255,
            node.offset_freq
        ])

        node.send(
            ack_header + ack
        )

        # ----------------------------------------------------
        # ALL CHUNKS RECEIVED
        # ----------------------------------------------------

        if len(chunks) == total:

            result = b"".join(
                chunks[i]
                for i in range(total)
            )

            if expected_size is not None and len(result) != expected_size:
                raise RuntimeError(
                    f"Received {len(result)} bytes but expected {expected_size}"
                )

            return result



