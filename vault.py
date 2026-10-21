# file encrypter w/ password + google authenticator 2FA
#
#   python3 vault.py setup              # one time, scan the QR with your phone
#   python3 vault.py encrypt secret.pdf # -> secret.pdf.enc
#   python3 vault.py decrypt secret.pdf.enc
#
# AES-256-GCM, key comes from scrypt(password + totp secret).
# so you need the password AND the secret on this machine, and the
# tool won't even try decrypting without a valid 6 digit code.

import getpass
import os
import sys

import pyotp
import qrcode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SECRET_FILE = os.path.expanduser("~/.vault_totp")
MAGIC = b"VLT1"  # so we can tell our files apart


def load_secret():
    if not os.path.exists(SECRET_FILE):
        sys.exit("no 2FA set up yet. run: python3 vault.py setup")
    with open(SECRET_FILE) as f:
        return f.read().strip()


def derive_key(password, secret, salt):
    # scrypt is slow on purpose so brute forcing passwords sucks
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode() + secret.encode())


def check_code(secret, code):
    # valid_window=1 lets the code from 30s before/after work too (phone clock drift)
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def encrypt_bytes(data, password, secret):
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    key = derive_key(password, secret, salt)
    # header goes in as associated data, so messing with it breaks decryption
    return header + AESGCM(key).encrypt(nonce, data, header)


def decrypt_bytes(blob, password, secret):
    if blob[:4] != MAGIC:
        raise ValueError("not a vault file")
    header, ct = blob[:32], blob[32:]
    salt, nonce = header[4:20], header[20:32]
    key = derive_key(password, secret, salt)
    return AESGCM(key).decrypt(nonce, ct, header)  # throws InvalidTag if wrong


def setup():
    if os.path.exists(SECRET_FILE):
        if input("2FA already set up. overwrite? old .enc files will be unrecoverable (y/N) ").lower() != "y":
            return
    secret = pyotp.random_base32()
    # open w/ 600 perms from the start so it's never world readable
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret)

    uri = pyotp.TOTP(secret).provisioning_uri(name=getpass.getuser(), issuer_name="FileVault")
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.print_ascii(invert=True)
    print("scan that with google authenticator (or authy etc)")
    print("can't scan? enter this key manually:", secret)

    code = input("\nenter the 6 digit code to confirm: ").strip()
    print("good to go" if check_code(secret, code) else "code didn't match, run setup again")


def encrypt(path):
    secret = load_secret()
    pw = getpass.getpass("password: ")
    if len(pw) < 8:
        sys.exit("use at least 8 chars")
    if pw != getpass.getpass("again: "):
        sys.exit("passwords don't match")

    with open(path, "rb") as f:
        blob = encrypt_bytes(f.read(), pw, secret)
    out = path + ".enc"
    with open(out, "wb") as f:
        f.write(blob)
    print(f"encrypted -> {out}")
    print("original is still there, delete it yourself once you've checked decrypt works")


def decrypt(path):
    secret = load_secret()
    code = input("2FA code: ").strip()
    if not check_code(secret, code):
        sys.exit("bad code")
    pw = getpass.getpass("password: ")

    with open(path, "rb") as f:
        blob = f.read()
    try:
        data = decrypt_bytes(blob, pw, secret)
    except InvalidTag:
        sys.exit("wrong password (or the file got tampered with)")
    except ValueError as e:
        sys.exit(str(e))

    out = path[:-4] if path.endswith(".enc") else path + ".dec"
    if os.path.exists(out):
        out += ".dec"  # don't clobber anything
    with open(out, "wb") as f:
        f.write(data)
    print(f"decrypted -> {out}")


if __name__ == "__main__":
    cmds = {"setup": setup, "encrypt": encrypt, "decrypt": decrypt}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__ or "usage: vault.py setup | encrypt <file> | decrypt <file.enc>")
    if sys.argv[1] == "setup":
        setup()
    elif len(sys.argv) < 3:
        sys.exit(f"usage: vault.py {sys.argv[1]} <file>")
    else:
        cmds[sys.argv[1]](sys.argv[2])
