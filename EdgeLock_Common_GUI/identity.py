"""Fresh ML-DSA-65 identity every run; SE050E storage via SCP03.

NOTE: liboqs generates and signs in Pi RAM. SE050E binary objects are exportable.
"""
import hashlib
import oqs
from se050_bridge import replace_identity, read_own_public, read_own_secret

SIG = "ML-DSA-65"

def provision_fresh():
    with oqs.Signature(SIG) as signer:
        public = signer.generate_keypair()
        secret = signer.export_secret_key()
        proof = signer.sign(b"fresh-identity-self-test")
    with oqs.Signature(SIG) as verifier:
        if not verifier.verify(b"fresh-identity-self-test",proof,public):
            raise RuntimeError("Fresh key pair failed verification")
    # This operation deliberately replaces the two reserved persistent objects.
    replace_identity(public,secret)
    stored_public=read_own_public()
    stored_secret=read_own_secret()
    if stored_public[:32]!=stored_secret[:32]:
        raise RuntimeError("Stored ML-DSA public/private seed mismatch")
    with oqs.Signature(SIG,stored_secret) as signer:
        signature=signer.sign(b"stored-identity-check")
    with oqs.Signature(SIG) as verifier:
        if not verifier.verify(b"stored-identity-check",signature,stored_public):
            raise RuntimeError("Stored identity verification failed")
    print("PASS: fresh ML-DSA identity in EdgeLock")
    print("Own fingerprint:",hashlib.sha256(stored_public).hexdigest())
    return stored_public

def signing_secret():
    return read_own_secret()  # transient export into Pi RAM for liboqs
