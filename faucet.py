#!/usr/bin/env python3
import requests
import sys
import json

def main():
    if len(sys.argv) < 3:
        print("Użycie: faucet.py <ADDRESS> <AMOUNT> [URL]")
        print("Domyślnie URL = http://127.0.0.1:8000")
        sys.exit(1)

    address = sys.argv[1]
    amount = float(sys.argv[2])
    base_url = "http://127.0.0.1:8000"
    if len(sys.argv) >= 4:
        base_url = sys.argv[3].rstrip("/")

    data = {"address": address, "amount": amount}
    url = f"{base_url}/faucet"
    try:
        resp = requests.post(url, json=data)
        if resp.status_code == 200:
            print("Faucet OK:", resp.json())
        else:
            print("Faucet Error:", resp.json())
    except Exception as e:
        print("Błąd:", e)

if __name__ == "__main__":
    main()
