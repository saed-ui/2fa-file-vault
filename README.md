# 2fa-file-vault

encrypts any file (pdf, image, whatever) with AES-256 and won't decrypt it unless you give the right password **and** a code from google authenticator on your phone.

## setup

```
pip install -r requirements.txt
python3 vault.py setup
```

prints a QR code in the terminal, scan it with google authenticator / authy / microsoft authenticator. it asks for one code to make sure it worked.

## use

```
python3 vault.py encrypt taxes.pdf        # -> taxes.pdf.enc
python3 vault.py decrypt taxes.pdf.enc    # asks for 2FA code, then password
```

it doesn't delete your original after encrypting. check decrypt works first, then delete it yourself.

## how it works

- **AES-256-GCM** for the actual encryption. GCM also catches tampering, if anyone flips a single bit decrypt fails instead of giving you garbage
- the key comes from **scrypt**(password + totp secret, random salt). scrypt is slow and eats memory on purpose so guessing passwords is expensive
- new random salt + nonce for every file, stored at the start of the `.enc` file:

```
VLT1 | salt (16) | nonce (12) | ciphertext + tag
```

- the TOTP secret lives in `~/.vault_totp` (chmod 600). since it's mixed into the key, someone who steals just the `.enc` file and your password still can't open it

## being honest about the 2FA part

the 6 digit code itself can't be part of the key (it changes every 30s, you'd never decrypt again). so the code check is a gate in the program, and the real protection is password + the secret file on your machine. if someone has your whole machine they could skip the code check. that's the same tradeoff most local 2FA tools make, but good to know.

**don't lose `~/.vault_totp`**. if it's gone, your files are gone. no recovery.

## todo maybe
- lock out after X wrong codes
- encrypt whole folders
- simple GUI
