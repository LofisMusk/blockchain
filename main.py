#!/usr/bin/env python3

import argparse
from p2p import Node

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p2p-port", type=int, default=5000, help="Port P2P")
    parser.add_argument("--api-port", type=int, default=8000, help="Port API (HTTP)")
    parser.add_argument("--connect", type=str, default="", help="host:port do innego węzła")
    args = parser.parse_args()

    # Tworzymy węzeł
    node = Node(host="127.0.0.1", port=args.p2p_port, api_port=args.api_port)
    # Uruchamiamy serwery (P2P oraz API)
    node.start_server()

    # Jeśli podano --connect, łączymy się z innym węzłem
    if args.connect:
        try:
            host, cport = args.connect.split(":")
            cport = int(cport)
            node.connect_to_peer(host, cport)
            print(f"Połączono z węzłem: {host}:{cport}")
        except:
            print("Błąd parametru --connect. Użyj: --connect 127.0.0.1:5001")

    print(f"Uruchomiono węzeł P2P na porcie {args.p2p_port}, API na porcie {args.api_port}.")
    print("Możesz teraz korzystać z P2P, a także z endpointów HTTP na http://127.0.0.1:8000")

    # Ewentualnie prosta pętla do wprowadzania komend (CLI)
    print("Wpisz 'exit' aby zakończyć.")
    while True:
        cmd = input(">> ").strip()
        if cmd == "exit":
            print("Zamykanie węzła...")
            break
        elif cmd:
            print("Nieznana komenda, spróbuj 'exit'.")

if __name__ == "__main__":
    main()
