from web3 import Web3
from eth_account.messages import encode_defunct
import eth_account
import os

def get_keys(challenge: bytes, filename: str = "secret_key.txt"):
    """
    Called by the autograder with a random byte-challenge.
    Returns (signature_hex, checksummed_address).
    """

    # 1. Load private key from file
    with open(filename, "r") as f:
        raw_key = f.readline().strip()
    if not raw_key:
        raise ValueError("secret_key.txt is empty")
    if not raw_key.startswith("0x"):
        raw_key = "0x" + raw_key                  # normalise

    # 2. Instantiate account from key
    w3 = Web3()
    acct = w3.eth.account.from_key(raw_key)
    addr = Web3.to_checksum_address(acct.address)

    # 3. Sign the challenge (EIP-191 defunct message)
    msg = encode_defunct(challenge)
    sig = acct.sign_message(msg).signature.hex()

    # 4. Sanity-check (recover address must match)
    recovered = eth_account.Account.recover_message(msg, signature=sig)
    if recovered.lower() != addr.lower():
        raise ValueError("signature verification failed")

    return sig, addr


# Handy local check: prints your address 3×
if __name__ == "__main__":
    for _ in range(3):
        print(get_keys(os.urandom(32))[1])
