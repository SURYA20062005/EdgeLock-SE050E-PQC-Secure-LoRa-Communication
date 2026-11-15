"""Mutual challenge-response with signed role- and session-bound transcripts."""
import secrets
import oqs
from se050_bridge import read_peer
from identity import signing_secret
from lora_transport import send_complete,receive_complete

DOMAIN=b"EDGELOCK-SCP03-FRESH-V2|"

def authenticate(role):
    peer=read_peer()
    secret=signing_secret()
    with oqs.Signature("ML-DSA-65",secret) as signer, oqs.Signature("ML-DSA-65") as verifier:
        sig_len=signer.details["length_signature"]
        if role=="Bob":
            cb=secrets.token_bytes(32)
            send_complete(cb)
            packet=receive_complete(32+sig_len)
            ca,signature=packet[:32],packet[32:]
            transcript=DOMAIN+cb+ca
            if not verifier.verify(transcript+b"|ALICE",signature,peer):
                raise RuntimeError("Alice authentication FAILED: STOP")
            send_complete(signer.sign(transcript+b"|BOB"))
        else:
            cb=receive_complete(32)
            ca=secrets.token_bytes(32)
            transcript=DOMAIN+cb+ca
            send_complete(ca+signer.sign(transcript+b"|ALICE"))
            signature=receive_complete(sig_len)
            if not verifier.verify(transcript+b"|BOB",signature,peer):
                raise RuntimeError("Bob authentication FAILED: STOP")
    print("PASS: mutual ML-DSA-65 authentication")
    return transcript
