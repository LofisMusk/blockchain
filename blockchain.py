#!/usr/bin/env python3
from stake import StakeManager
import time
import hashlib
import random
from wallet import Wallet  # import klasy Wallet do weryfikacji podpisów

class Transaction:
    """
    Transakcja:
    - public_key_hex: nadawca
    - receiver: odbiorca (np. klucz publiczny lub inny identyfikator)
    - amount: kwota
    - signature: podpis transakcji (hex)
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

    def sign_transaction(self, private_key_hex):
        """
        Podpisujemy transakcję kluczem prywatnym.
        """
        message = f"{self.public_key_hex}{self.receiver}{self.amount}"
        w = Wallet(private_key_hex)
        self.signature = w.sign(message)

    def is_valid(self):
        """
        Sprawdzamy ważność transakcji, czyli poprawność podpisu.
        Zakładamy, że public_key_hex != "".
        """
        if not self.public_key_hex or not self.signature:
            return False
        message = f"{self.public_key_hex}{self.receiver}{self.amount}"
        return Wallet.verify_signature(self.public_key_hex, message, self.signature)

class Block:
    """
    Blok w łańcuchu:
    - index
    - previous_hash
    - transactions (lista obiektów Transaction)
    - validator (klucz publiczny walidatora)
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
            str([tx.to_dict() for tx in self.transactions]) +
            str(self.validator) +
            str(self.timestamp)
        )
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "validator": self.validator,
            "timestamp": self.timestamp,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(d):
        transactions = [Transaction.from_dict(t) for t in d["transactions"]]
        b = Block(d["index"], d["previous_hash"], transactions, d["validator"], d["timestamp"])
        b.hash = d["hash"]  # Ustawiamy hash z oryginału, aby zachować zgodność
        return b

class ProofOfStakeBlockchain:
    def __init__(self):
        self.stake_manager = StakeManager()
        # Kładziemy tu cokolwiek jeszcze nam potrzebne.

        # Możesz od razu tworzyć blok genesis:
        genesis_block = Block(0, "0", [], "GENESIS")
        self.stake_manager.chain.append(genesis_block)

    def mine_block(self):
        return self.stake_manager.mine_block()

    def stake_tokens(self, pubkey, amt):
        return self.stake_manager.stake_tokens(pubkey, amt)

    def get_balance(self, address):
        return self.stake_manager.get_balance(address)

    def add_balance(self, address, amount):
        return self.stake_manager.add_balance(address, amount)

    def to_dict(self):
        return self.stake_manager.to_dict()

    @staticmethod
    def from_dict(d):
        bc = ProofOfStakeBlockchain()
        bc.chain = [Block.from_dict(b) for b in d["chain"]]
        bc.pending_transactions = [Transaction.from_dict(t) for t in d["pending_transactions"]]
        bc.stakes = d["stakes"]
        return bc
