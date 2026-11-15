"""Signed ML-KEM-512 key establishment; HKDF; session key imported via SCP03."""
import hashlib, secrets, struct
import oqs
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from se050_bridge import read_peer,import_session_key
from identity import signing_secret
from lora_transport import send_complete,receive_complete

KEM="ML-KEM-512"
CTX=b"EDGELOCK-SCP03-FRESH-V2|MLKEM512|AES256GCM"

def establish(role, auth_transcript):
    peer=read_peer()
    secret_key=signing_secret()
    with oqs.Signature("ML-DSA-65",secret_key) as signer, oqs.Signature("ML-DSA-65") as verifier, oqs.KeyEncapsulation(KEM) as kem:
        sig_len=signer.details["length_signature"]
        pk_len=kem.details["length_public_key"]
        ct_len=kem.details["length_ciphertext"]
        if role=="Alice":
            sid=secrets.token_bytes(16)
            pk=kem.generate_keypair()
            request=b"KEM-ALICE|"+auth_transcript+sid+pk
            send_complete(sid+pk+signer.sign(request))
            response=receive_complete(16+ct_len+sig_len)
            if response[:16]!=sid: raise RuntimeError("Session mismatch: STOP")
            ct=response[16:16+ct_len]
            sig=response[16+ct_len:]
            if not verifier.verify(b"KEM-BOB|"+request+ct,sig,peer):
                raise RuntimeError("Bob ciphertext signature invalid: STOP")
            shared=kem.decap_secret(ct)
        else:
            request_packet=receive_complete(16+pk_len+sig_len)
            sid=request_packet[:16]
            pk=request_packet[16:16+pk_len]
            sig=request_packet[16+pk_len:]
            request=b"KEM-ALICE|"+auth_transcript+sid+pk
            if not verifier.verify(request,sig,peer):
                raise RuntimeError("Alice KEM public-key signature invalid: STOP")
            ct,shared=kem.encap_secret(pk)
            send_complete(sid+ct+signer.sign(b"KEM-BOB|"+request+ct))
        salt=hashlib.sha256(auth_transcript+sid).digest()
        key=HKDF(master=shared,key_len=32,salt=salt,hashmod=SHA256,context=CTX)
        import_session_key(key)
        del key,shared
    print("PASS: new AES-256 key imported into SE050E via SCP03")
    return sid
