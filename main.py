"""Single Thonny entrypoint: run Bob first, then Alice."""
from se050_bridge import EXE
from identity import provision_fresh
from pairing import exchange
from authentication import authenticate
from key_exchange import establish
from messaging import send_message,receive_message

# Shared command-line entrypoint; use GUI for role selection.
import argparse
ROLE=None

def main():
    global ROLE
    parser=argparse.ArgumentParser()
    parser.add_argument("--role",choices=("Alice","Bob"),required=True)
    ROLE=parser.parse_args().role
    if not EXE.exists():
        raise RuntimeError("SCP03 bridge not built. First run: python se050_bridge.py")
    print("ROLE:",ROLE)
    print("WARNING: this run ERASES/REPLACES the three reserved identity/peer objects.")
    print("This is a lab-only fresh-identity demo. Verify peer fingerprint out-of-band.")
    if input("Type REKEY to authorize reserved-object replacement: ").strip()!="REKEY":
        raise RuntimeError("Cancelled; no objects modified")
    provision_fresh()
    exchange(ROLE)
    transcript=authenticate(ROLE)
    sid=establish(ROLE,transcript)
    if ROLE=="Alice": send_message(sid)
    else: receive_message(sid)
    print("COMPLETE")

if __name__=="__main__":
    try: main()
    except Exception as e:
        print("STOPPED:",type(e).__name__,str(e))
        raise
    finally:
        try:
            from lora_transport import node
            node.ser.close()
        except Exception: pass
