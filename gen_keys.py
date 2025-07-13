from web3 import Web3
from eth_account.messages import encode_defunct
import eth_account
import os

def sign_message(challenge: bytes, filename: str = "secret_key.txt"):
    """
    Read your private key from `filename`, sign `challenge`, 
    verify the signature, and return (signed_message, address).

    Autograder will check:
      1. Signature recovers to the returned address.
      2. That address has nonzero testnet balances on BSC and Avalanche.
    """
    # 1. Read and normalize private key
    with open(filename, "r") as f:
        raw_key = f.readline().strip()
    if not raw_key:
        raise ValueError(f"{filename} is empty")
    if not raw_key.startswith("0x"):
        raw_key = "0x" + raw_key

    # 2. Instantiate Web3 account
    w3 = Web3()
    acct = w3.eth.account.from_key(raw_key)
    eth_addr = acct.address

    # 3. Prepare the EIP-191 message
    message = encode_defunct(challenge)

    # 4. Sign
    signed_message = acct.sign_message(message)

    # 5. Verify we recover the same address
    recovered = eth_account.Account.recover_message(
        message,
        signature=signed_message.signature.hex()
    )
    if recovered.lower() != eth_addr.lower():
        raise ValueError("Signature verification failed")

    # 6. Return the full SignedMessage object and address
    return signed_message, eth_addr

if __name__ == "__main__":
    # Quick local check: prints your address 4×
    for _ in range(4):
        challenge = os.urandom(64)
        _, addr = sign_message(challenge)
        print(addr)
