from web3 import Web3
from eth_account.messages import encode_defunct
import eth_account
import os


def sign_message(challenge: bytes, filename: str = "secret_key.txt"):
    """
    challenge – random byte string provided by the autograder
    filename  – path to a file that holds ONE line: your 32-byte private key
                (64 hex chars) with or without the 0x prefix.

    Returns (signed_message, address).

    The address must hold testnet funds on both BSC and Avalanche.
    """

    # --- 1. Read & normalise the private key -------------------------------
    with open(filename, "r") as f:
        raw_key = f.readline().strip()
    if not raw_key:
        raise ValueError(f"{filename} is empty")
    if not raw_key.startswith("0x"):
        raw_key = "0x" + raw_key

    # --- 2. Instantiate the account ----------------------------------------
    w3 = Web3()
    acct = w3.eth.account.from_key(raw_key)
    eth_addr = w3.to_checksum_address(acct.address)

    # --- 3. Sign the challenge (EIP-191 / “defunct”) -----------------------
    message = encode_defunct(challenge)
    signed_message = acct.sign_message(message)

    # --- 4. Verify (defensive check) ---------------------------------------
    recovered = eth_account.Account.recover_message(
        message,
        signature=signed_message.signature.hex()
    )
    assert recovered.lower() == eth_addr.lower(), "Signature verification failed"

    # --- 5. Return ----------------------------------------------------------
    return signed_message, eth_addr


if __name__ == "__main__":
    # simple sanity-check: prints the address 4×
    for _ in range(4):
        sig, addr = sign_message(os.urandom(64))
        print(addr)
