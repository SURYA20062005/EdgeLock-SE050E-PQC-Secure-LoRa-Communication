"""SE050E helper: compile once; peer public key and AES session key stay in SE050E."""
from pathlib import Path
import os, subprocess, struct, secrets, hashlib
BASE=Path.home()/"plug-and-trust"
PROJECT=BASE/"pqc_lora_bridge"
EXE=PROJECT/"build_scp03_app"/"se050_bridge"
PEER_ID="0x7A050A31"
AES_ID="0x7A05F041"
OWN_PUBLIC_ID="0x7A050A28"
OWN_SECRET_ID="0x7A050A29"

def build():
    if not (BASE/"simw_lib.cmake").exists(): raise RuntimeError("NXP middleware missing: "+str(BASE))
    PROJECT.mkdir(exist_ok=True)
    source=Path(__file__).with_name("se050_bridge.c")
    if not source.exists(): raise RuntimeError("Place se050_bridge.c beside this Python file")
    target=PROJECT/"se050_bridge.c"
    if target.exists() and target.read_bytes()!=source.read_bytes():
        backup=PROJECT/"se050_bridge.c.before_scp03"
        if not backup.exists(): backup.write_bytes(target.read_bytes())
    target.write_bytes(source.read_bytes())
    (PROJECT/"CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.10)
project(se050_bridge C)
set(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
include(${SIMW_LIB_DIR}/simw_lib.cmake)
if("${PTMW_SE05X_Auth}" STREQUAL "None")
 add_executable(se050_bridge ${SIMW_SE_SOURCES} se050_bridge.c)
else()
 add_executable(se050_bridge ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES} se050_bridge.c)
endif()
target_include_directories(se050_bridge PUBLIC ../ ${SIMW_INC_DIR})
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
target_link_libraries(se050_bridge PRIVATE OpenSSL::Crypto)
''')
    for args in (["cmake","-S",str(PROJECT),"-B",str(PROJECT/"build_scp03_app"),"-DPTMW_Applet=SE050_E","-DPTMW_SE05X_Ver=07_02","-DPTMW_SE05X_Auth=PlatfSCP03","-DPTMW_HostCrypto=OPENSSL","-DSSSFTR_SE05X_RSA=0"], ["cmake","--build",str(PROJECT/"build_scp03_app"),"-j2"]):
        p=subprocess.run(args,capture_output=True,text=True,timeout=240)
        if p.returncode: raise RuntimeError(p.stdout+"\n"+p.stderr)
    print("EdgeLock bridge compiled:",EXE)

def call(cmd,data=b"",output=False):
    if not EXE.exists(): raise RuntimeError("Build bridge first: python3 se050_bridge.py")
    payload=cmd.encode()+b"\n"+struct.pack(">I",len(data))+data
    p=subprocess.run([str(EXE),os.environ.get("SE050_PORT","/dev/i2c-1:72")],input=payload,capture_output=True,timeout=90)
    if p.returncode:
        raise RuntimeError("SE050E operation failed (%s): %s\n%s"%(cmd,p.stdout.decode(errors="replace")[-1800:],p.stderr.decode(errors="replace")[-1000:]))
    if output:
        lines=[x for x in p.stdout.decode(errors="replace").splitlines() if x.startswith("RESULT:")]
        if len(lines)!=1: raise RuntimeError("No result returned by SE050E: "+p.stdout.decode(errors="replace")[-1500:])
        return bytes.fromhex(lines[0][7:])

def reset_identity():
    raise RuntimeError("Disabled: this SCP03 project preserves existing identities")

def reset_all_four_keys():
    raise RuntimeError("Disabled: this SCP03 project preserves existing persistent keys")

def provision_identity(public, secret):
    if len(public)!=1952 or len(secret)!=4032:
        raise ValueError("ML-DSA-65 key lengths must be 1952 and 4032 bytes")
    # Never automatically overwrite a long-term identity.
    call("own-write", public+secret)
    if read_own_public()!=public:
        raise RuntimeError("Stored ML-DSA public key mismatch")
    if read_own_secret()!=secret:
        raise RuntimeError("Stored ML-DSA private key mismatch")

def replace_identity(public, secret):
    if len(public)!=1952 or len(secret)!=4032:
        raise ValueError("Incorrect ML-DSA-65 key lengths")
    call("own-replace", public+secret)
    if read_own_public()!=public or read_own_secret()!=secret:
        raise RuntimeError("Identity readback mismatch; abort")


def replace_peer(public):
    if len(public)!=1952: raise ValueError("Incorrect peer public key length")
    call("peer-replace",public)
    if read_peer()!=public: raise RuntimeError("Peer public key readback mismatch")

def read_own_public():
    value=call("own-public",output=True)
    if len(value)!=1952: raise RuntimeError("Invalid ML-DSA public key in EdgeLock")
    return value

def read_own_secret():
    value=call("own-secret",output=True)
    if len(value)!=4032: raise RuntimeError("Invalid ML-DSA private key in EdgeLock")
    return value

def provision_peer(public):
    if len(public)!=1952: raise ValueError("Expected 1952-byte ML-DSA-65 public key")
    call("peer-write",public)
    if read_peer()!=public: raise RuntimeError("SE050E peer public-key readback mismatch")

def read_peer():
    p=call("peer-read",output=True)
    if len(p)!=1952: raise RuntimeError("Unexpected peer public key size")
    return p

def import_session_key(key):
    if len(key)!=32: raise ValueError("AES-256 requires 32 bytes")
    call("aes-import",key)

def encrypt(plaintext,aad):
    if len(plaintext)>4096: raise ValueError("This first hardware test supports <=4096-byte plaintext")
    nonce=secrets.token_bytes(12)
    packet=nonce+struct.pack(">HH",len(aad),len(plaintext))+aad+plaintext
    ct_tag=call("encrypt",packet,output=True)
    if len(ct_tag)!=len(plaintext)+16: raise RuntimeError("Invalid SE050E encryption output")
    return nonce,ct_tag[:-16],ct_tag[-16:]

def decrypt(nonce,ciphertext,tag,aad):
    if len(nonce)!=12 or len(tag)!=16 or len(ciphertext)>4096: raise ValueError("Invalid GCM input")
    packet=nonce+struct.pack(">HH",len(aad),len(ciphertext))+tag+aad+ciphertext
    plaintext=call("decrypt",packet,output=True)
    if len(plaintext)!=len(ciphertext): raise RuntimeError("Invalid decrypted length")
    return plaintext

if __name__=="__main__":build()
