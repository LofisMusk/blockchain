#!/usr/bin/env python3
import random
import time
import hashlib

# Zakładam, że Transaction i Block masz w osobnym pliku – np. w blockchain.py
# Możesz je tutaj zaimportować, jeśli ich potrzebujesz.
from blockchain import Block, Transaction

class StakeManager:
    """
    Klasa odpowiedzialna za mechanikę Proof of Stake:
      - przechowywanie staków
      - wybór walidatora
      - tworzenie nowych bloków (mine_block)
      - zarządzanie saldami
    """

    def __init__(self, chain=None, pending_transactions=None, stakes=None, balances=None):
        # Jeśli któraś struktura nie jest podana, inicjalizujemy pustą
        self.chain = chain if chain is not None else []
        self.pending_transactions = pending_transactions if pending_transactions is not None else []
        self.stakes = stakes if stakes is not None else {}
        self.balances = balances if balances is not None else {}

    def stake_tokens(self, public_key, amount):
        """Dodaje 'amount' do stanu stakowanego przez 'public_key' (o ile ma saldo)."""
        current_stake = self.stakes.get(public_key, 0)
        current_balance = self.balances.get(public_key, 0)
        if current_balance < amount:
            return False  # brak środków
        self.stakes[public_key] = current_stake + amount
        self.balances[public_key] = current_balance - amount
        return True

    def get_validators(self):
        """Zwraca słownik public_key -> staked_amount (tylko > 0)."""
        return {k: v for k, v in self.stakes.items() if v > 0}

    def select_validator(self):
        """Losowy wybór walidatora z wagą = staked_amount."""
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

    def add_balance(self, address, amount):
        """Dodaje 'amount' do stanu konta address."""
        bal = self.balances.get(address, 0)
        self.balances[address] = bal + amount
        return self.balances[address]

    def get_balance(self, address):
        """Zwraca saldo adresu."""
        return self.balances.get(address, 0)

    def mine_block(self):
        """
        Losuje walidatora, tworzy nowy blok z self.pending_transactions,
        przyznaje nagrodę walidatorowi, dodaje blok do self.chain.
        """
        validator = self.select_validator()
        if not validator:
            print("[StakeManager] Brak stakerów – blok nie powstanie.")
            return None

        # Tworzymy blok – musisz mieć zdefiniowaną klasę Block i Transaction
        index = len(self.chain)
        previous_hash = self.chain[-1].hash if self.chain else "0"
        new_block = Block(
            index=index,
            previous_hash=previous_hash,
            transactions=self.pending_transactions[:],  # kopia
            validator=validator
        )

        self.chain.append(new_block)
        self.pending_transactions.clear()

        # Nagroda
        reward_amount = 10
        self.add_balance(validator, reward_amount)
        coinbase_tx = Transaction("", validator, reward_amount, signature="REWARD")
        # Możesz chcieć od razu dodać transakcję do next pending, albo do samego bloku – Twój wybór.
        self.pending_transactions.append(coinbase_tx)

        print(f"[StakeManager] Walidator {validator} utworzył blok {index}, nagroda = {reward_amount}")
        return new_block

    def to_dict(self):
        """Seryjnie zapakować dane do dict (np. do zapisu)."""
        return {
            "chain": [b.to_dict() for b in self.chain],
            "pending_transactions": [t.to_dict() for t in self.pending_transactions],
            "stakes": self.stakes,
            "balances": self.balances
        }

    @staticmethod
    def from_dict(data):
        """Odtworzyć stan stake-managera z dict."""
        # Zakładamy, że Block i Transaction są importowane z blockchain.py
        # Jeśli tak – musisz tu jawnie odtworzyć blocki i transakcje
        from blockchain import Block, Transaction
        manager = StakeManager()
        manager.chain = [Block.from_dict(bd) for bd in data["chain"]]
        manager.pending_transactions = [Transaction.from_dict(td) for td in data["pending_transactions"]]
        manager.stakes = data["stakes"]
        manager.balances = data["balances"]
        return manager
