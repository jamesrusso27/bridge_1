from web3 import Web3
from eth_account.messages import encode_defunct
import eth_account
import os

def sign_message(challenge: bytes, filename: str = "secret_key.txt"):
    # Read private key
    with open(filename, "r") as f:
        raw_key = f.readline().strip()
    if not raw_key:
        raise ValueError(f"{filename} is empty")
    if not raw_key.startswith("0x"):
        raw_key = "0x" + raw_key

    # Load account from key
    w3 = Web3()
    acct = w3.eth.account.from_key(raw_key)
    eth_addr = acct.address

    # Sign the challenge
    message = encode_defunct(challenge)
    signed_message = acct.sign_message(message)

    # Verify signature
    recovered = eth_account.Account.recover_message(
        message,
        signature=signed_message.signature.hex()
    )
    if recovered.lower() != eth_addr.lower():
        raise ValueError("Signature verification failed")

    return signed_message, eth_addr

if __name__ == "__main__":
    for _ in range(4):
        challenge = os.urandom(64)
        _, addr = sign_message(challenge)
        print(addr)
