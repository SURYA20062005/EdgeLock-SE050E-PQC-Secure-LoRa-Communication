"""Exchange public keys over LoRa; require independent fingerprint confirmation."""
import hashlib
from se050_bridge import read_own_public, read_peer, replace_peer
from lora_transport import send_complete, receive_complete

def exchange(role):
    own=read_own_public()
    if role=="Alice":
        print("Sending Alice public key")
        send_complete(own)
        print("Waiting for Bob public key")
        peer=receive_complete(1952)
    else:
        print("Waiting for Alice public key")
        peer=receive_complete(1952)
        print("Sending Bob public key")
        send_complete(own)
    if len(peer)!=1952: raise RuntimeError("Incorrect peer key length")
    digest=hashlib.sha256(peer).hexdigest()
    print("RECEIVED peer SHA-256:",digest)
    print("Verify this fingerprint through an independent trusted channel, NOT this LoRa link.")
    typed=input("Type the independently verified 64-character peer SHA-256: ").strip().lower()
    if typed!=digest:
        raise RuntimeError("Peer fingerprint not verified: STOP")
    replace_peer(peer)
    if read_peer()!=peer: raise RuntimeError("Peer EdgeLock readback mismatch")
    print("PASS: authenticated peer key stored in EdgeLock")
