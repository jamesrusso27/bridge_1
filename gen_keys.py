from web3 import Web3
from eth_account.messages import encode_defunct
import eth_account
import os

def sign_message(challenge: bytes, filename: str = "secret_key.txt"):
    # 1. Read your 32-byte private key from secret_key.txt
    with open(filename, "r") as f:
        raw_key = f.readline().strip()
    if not raw_key:
        raise ValueError(f"{filename} is empty")
    if not raw_key.startswith("0x"):
        raw_key = "0x" + raw_key

    # 2. Load that key into Web3
    w3 = Web3()
    acct = w3.eth.account.from_key(raw_key)
    eth_addr = acct.address

    # 3. Encode & sign the random challenge
    message = encode_defunct(challenge)
    signed_message = acct.sign_message(message)

    # 4. Sanity-check: recovered must equal acct.address
    recovered = eth_account.Account.recover_message(
        message,
        signature=signed_message.signature.hex()
    )
    if recovered.lower() != eth_addr.lower():
        raise ValueError("Signature verification failed")

    # 5. Return the signature object and your funded address
    return signed_message, eth_addr

if __name__ == "__main__":
    # Quick local check: prints your address 4×
    for _ in range(4):
        challenge = os.urandom(64)
        _, addr = sign_message(challenge)
        print(addr)
