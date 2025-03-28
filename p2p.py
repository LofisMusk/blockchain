#!/usr/bin/env python3
import socket
import threading
import json
import time
import hashlib
import random
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

################################################################################
#  PROSTE KLASY BLOCK i TRANSACTION
################################################################################

class Transaction:
    """
    Transakcja:
      - public_key_hex (nadawca)
      - receiver (odbiorca)
      - amount (kwota)
      - signature (podpis, tu uproszczony)
    """
    def __init__(self, public_key_hex, receiver, amount, signature=""):
        self.public_key_hex = public_key_hex
        self.receiver = receiver
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            "public_key_hex": self.public_key_hex,
            "receiver": self.receiver,
            "amount": self.amount,
            "signature": self.signature
        }

    @staticmethod
    def from_dict(d):
        return Transaction(
            d["public_key_hex"],
            d["receiver"],
            d["amount"],
            d["signature"]
        )

class Block:
    """
    Blok w łańcuchu:
      - index
      - previous_hash
      - transactions (lista Transaction)
      - validator
      - timestamp
      - hash
    """
    def __init__(self, index, previous_hash, transactions, validator, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.validator = validator
        self.timestamp = timestamp or time.time()
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = (
            str(self.index) +
            str(self.previous_hash) +
            str([t.to_dict() for t in self.transactions]) +
            str(self.validator) +
            str(self.timestamp)
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [t.to_dict() for t in self.transactions],
            "validator": self.validator,
            "timestamp": self.timestamp,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(d):
        txs = [Transaction.from_dict(tx) for tx in d["transactions"]]
        b = Block(d["index"], d["previous_hash"], txs, d["validator"], d["timestamp"])
        b.hash = d["hash"]
        return b

################################################################################
#  PROSTA IMPLEMENTACJA PO-S (ProofOfStakeBlockchain)
################################################################################

class ProofOfStakeBlockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.stakes = {}  # public_key -> stake amount

        # Dodatkowo: balances do prostego liczenia sald
        self.balances = {}

        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", [], "GENESIS")
        self.chain.append(genesis_block)

    def get_last_block(self):
        return self.chain[-1]

    def add_transaction(self, tx):
        # Uproszczona weryfikacja – sprawdzamy tylko, czy podpis jest "jakikolwiek"
        # W realnym systemie: weryfikacja klucza, sygnatury i salda
        if not tx.signature:
            return False
        self.pending_transactions.append(tx)
        return True

    def stake_tokens(self, public_key, amount):
        # W realnym systemie: sprawdzanie salda itp.
        staked = self.stakes.get(public_key, 0)
        self.stakes[public_key] = staked + amount
        # Odejmuje z balances, jeśli mamy taką mechanikę
        bal = self.balances.get(public_key, 0)
        if bal < amount:
            # Brak środków – w realnym systemie transakcja by się nie powiodła
            return False
        self.balances[public_key] = bal - amount
        return True

    def select_validator(self):
        total_stake = sum(self.stakes.values())
        if total_stake == 0:
            return None
        r = random.uniform(0, total_stake)
        cumulative = 0
        for staker, amt in self.stakes.items():
            cumulative += amt
            if r < cumulative:
                return staker
        return None

    def mine_block(self):
        validator = self.select_validator()
        if not validator:
            print("[CHAIN] Brak stakerów – blok nie powstanie.")
            return None

        new_block = Block(
            index=len(self.chain),
            previous_hash=self.get_last_block().hash,
            transactions=self.pending_transactions.copy(),
            validator=validator
        )
        self.chain.append(new_block)
        self.pending_transactions = []

        # Przykładowa nagroda:
        self.add_balance(validator, 10)
        # Dodaj "coinbase" transakcję
        coinbase_tx = Transaction("", validator, 10, signature="REWARD")
        self.pending_transactions.append(coinbase_tx)
        return new_block

    def add_balance(self, address, amount):
        # Metoda do powiększania salda - np. przez faucet
        bal = self.balances.get(address, 0)
        self.balances[address] = bal + amount
        return f"Nowe saldo {address} = {self.balances[address]}"

    def get_balance(self, address):
        return self.balances.get(address, 0)

    def replace_chain_if_longer(self, new_chain):
        if len(new_chain) > len(self.chain):
            # Minimalna weryfikacja
            self.chain = new_chain
            return True
        return False

    def to_dict(self):
        return {
            "chain": [b.to_dict() for b in self.chain],
            "pending_transactions": [t.to_dict() for t in self.pending_transactions],
            "stakes": self.stakes,
            "balances": self.balances
        }

    @staticmethod
    def from_dict(data):
        bc = ProofOfStakeBlockchain()
        bc.chain = [Block.from_dict(bd) for bd in data["chain"]]
        bc.pending_transactions = [Transaction.from_dict(td) for td in data["pending_transactions"]]
        bc.stakes = data["stakes"]
        bc.balances = data["balances"]
        return bc

################################################################################
#  GŁÓWNA KLASA WĘZŁA (Node) - P2P + API HTTP
################################################################################

class Node:
    def __init__(self, host="mekambe.ddns.net", port=5000, api_port=8000):
        self.host = host
        self.port = port
        self.api_host = host
        self.api_port = api_port

        self.peers = set()  # (host, port)
        self.blockchain = ProofOfStakeBlockchain()

    def start_server(self):
        # Uruchom serwer P2P w wątku
        t_p2p = threading.Thread(target=self.run_p2p_server, daemon=True)
        t_p2p.start()

        # Uruchom serwer HTTP w wątku
        t_api = threading.Thread(target=self.run_api_server, daemon=True)
        t_api.start()

        print(f"[NODE] Węzeł uruchomiony. P2P={self.port}, API={self.api_port}")

    ############################################################################
    # P2P
    ############################################################################
    def run_p2p_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(5)
        print(f"[P2P] Serwer nasłuchuje na {self.host}:{self.port}")
        while True:
            conn, addr = s.accept()
            t_client = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            t_client.start()

    def handle_client(self, conn, addr):
        data_buffer = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data_buffer += chunk
                while True:
                    try:
                        decoded = data_buffer.decode()
                        idx = decoded.find("}{")
                        if idx != -1:
                            part = decoded[:idx+1]
                            rest = decoded[idx+1:]
                            msg = json.loads(part)
                            self.handle_message(msg, conn, addr)
                            data_buffer = rest.encode()
                        else:
                            msg = json.loads(decoded)
                            self.handle_message(msg, conn, addr)
                            data_buffer = b""
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        break
            except ConnectionError:
                break
        conn.close()

    def handle_message(self, msg, conn, addr):
        mtype = msg.get("type")
        data = msg.get("data")
        if mtype == "NEW_TRANSACTION":
            tx = Transaction.from_dict(data)
            added = self.blockchain.add_transaction(tx)
            if added:
                print(f"[P2P] Dodano transakcję od {addr}")
                self.broadcast(msg)
        elif mtype == "NEW_BLOCK":
            block = Block.from_dict(data)
            last = self.blockchain.get_last_block()
            if block.previous_hash == last.hash:
                self.blockchain.chain.append(block)
                print(f"[P2P] Dodano nowy blok od {addr}, index={block.index}")
                self.broadcast(msg)
            else:
                print("[P2P] Blok nie pasuje, proszę o łańcuch")
                req = {"type": "REQUEST_CHAIN", "data": {}}
                conn.sendall(json.dumps(req).encode())
        elif mtype == "REQUEST_CHAIN":
            response = {
                "type": "CHAIN_DATA",
                "data": self.blockchain.to_dict()
            }
            conn.sendall(json.dumps(response).encode())
        elif mtype == "CHAIN_DATA":
            new_bc = ProofOfStakeBlockchain.from_dict(data)
            replaced = self.blockchain.replace_chain_if_longer(new_bc.chain)
            if replaced:
                print("[P2P] Zastąpiono łańcuch wersją od", addr)
        elif mtype == "PEERS":
            for p in data:
                self.peers.add(tuple(p))
        else:
            print(f"[P2P] Nieznany typ wiadomości {mtype}")

    def connect_to_peer(self, host, port):
        self.peers.add((host, port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            peer_msg = {
                "type": "PEERS",
                "data": list(self.peers)
            }
            s.sendall(json.dumps(peer_msg).encode())
            req = {"type": "REQUEST_CHAIN", "data": {}}
            s.sendall(json.dumps(req).encode())
            s.close()
        except:
            print("[P2P] Nie udało się połączyć z peerem:", host, port)

    def broadcast(self, msg):
        for (phost, pport) in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((phost, pport))
                s.sendall(json.dumps(msg).encode())
                s.close()
            except:
                pass

    def broadcast_block(self, block):
        msg = {
            "type": "NEW_BLOCK",
            "data": block.to_dict()
        }
        self.broadcast(msg)

    ############################################################################
    # API HTTP
    ############################################################################
    def run_api_server(self):
        class APIServerHandler(BaseHTTPRequestHandler):
            node_ref = self

            def _send_json(self, data, status=200):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                query = urllib.parse.parse_qs(parsed.query)

                if parsed.path == "/chain":
                    data = self.node_ref.blockchain.to_dict()
                    self._send_json(data)

                elif parsed.path == "/stake_info":
                    address = query.get("address", [""])[0]
                    stake_val = self.node_ref.blockchain.stakes.get(address, 0)
                    self._send_json({"address": address, "stake": stake_val})

                elif parsed.path == "/balance":
                    address = query.get("address", [""])[0]
                bal = self.node_ref.blockchain.get_balance(address)
                self._send_json({"address": address, "balance": bal})

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body)
                except:
                    self._send_json({"error": "Invalid JSON"}, 400)
                    return

                if parsed.path == "/transaction":
                    tx = Transaction.from_dict(payload)
                    added = self.node_ref.blockchain.add_transaction(tx)
                    if added:
                        # broadcast
                        msg = {"type": "NEW_TRANSACTION", "data": tx.to_dict()}
                        self.node_ref.broadcast(msg)
                        self._send_json({"status": "Transaction added"})
                    else:
                        self._send_json({"status": "Transaction rejected"}, 400)

                elif parsed.path == "/stake":
                    staker = payload.get("public_key_hex", "")
                    amount = payload.get("amount", 0)
                    ok = self.node_ref.blockchain.stake_tokens(staker, amount)
                if ok:
                    self._send_json({"status": "Stake updated"})
                else:
                    self._send_json({"status": "Stake failed"}, 400)


        httpd = HTTPServer((self.api_host, self.api_port), APIServerHandler)
        print(f"[API] Serwer HTTP na {self.api_host}:{self.api_port}")
        httpd.serve_forever()
