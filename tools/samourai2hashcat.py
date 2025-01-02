#!/usr/bin/env python

import base64
import json
import sys


def preprocess_samourai_wallet_backup(backup_file):
    with open(backup_file, "r") as f:
        backup = json.load(f)

    if backup["version"] != 2:
        raise ValueError("This script can only process version 2 of Samourai Wallet backups")

    payload_b64 = backup["payload"]
    payload_bin = base64.b64decode(payload_b64)

    if payload_bin[:8] != b"Salted__":
        raise ValueError("Invalid payload format: Missing Salted__ header")

    salt = payload_bin[8:16].hex()
    ciphertext = payload_bin[16:32].hex()

    print(f"samourai:{salt}:{ciphertext}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <samourai.txt>")
        sys.exit(1)

    preprocess_samourai_wallet_backup(sys.argv[1])
