"""AES-GCM performed by SE050E; only ciphertext crosses LoRa."""
import struct
from se050_bridge import encrypt,decrypt
from lora_transport import send_framed_complete,receive_complete,unframe_complete

def send_message(sid):
    text=input("Alice: type message to send to Bob: ")
    raw=text.encode("utf-8")
    if len(raw)>2048: raise ValueError("Text limit: 2048 UTF-8 bytes")
    aad=b"EDGELOCK-SCP03-FRESH-V2|A2B|"+sid
    nonce,ct,tag=encrypt(raw,aad)
    send_framed_complete(struct.pack(">H",len(raw))+nonce+ct+tag)
    print("PASS: ciphertext sent over LoRa")

def receive_message(sid):
    packet=unframe_complete(receive_complete(None))
    if len(packet)<30: raise RuntimeError("Short AES packet")
    n=struct.unpack(">H",packet[:2])[0]
    if n>2048 or len(packet)!=30+n: raise RuntimeError("Invalid AES packet length")
    nonce=packet[2:14]; ct=packet[14:14+n]; tag=packet[14+n:]
    aad=b"EDGELOCK-SCP03-FRESH-V2|A2B|"+sid
    plain=decrypt(nonce,ct,tag,aad)
    print("Bob decrypted message:",plain.decode("utf-8"))
