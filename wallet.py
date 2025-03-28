#!/usr/bin/env python3

import tkinter as tk
from tkinter import messagebox, simpledialog
import requests
import random

try:
    from ecdsa import SigningKey, SECP256k1
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False

###############################################################################
# PORTFEL
###############################################################################

class Wallet:
    """
    Prosta klasa portfela. Może generować klucz prywatny (ECDSA) lub importować z hex.
    Adres - uproszczony hash publicznego klucza (8 bajtów).
    """
    def __init__(self, private_key_hex=None):
        if ECDSA_AVAILABLE:
            if private_key_hex:
                self.sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
            else:
                self.sk = SigningKey.generate(curve=SECP256k1)
            self.vk = self.sk.get_verifying_key()
            
            self.private_key_hex = self.sk.to_string().hex()
            # "Adres" - 8 bajtów hex publicznego klucza
            pub_bytes = self.vk.to_string()
            self.address = pub_bytes.hex()[:16]
        else:
            # Jeżeli nie ma ecdsa, generujemy pseudo-unikat
            self.private_key_hex = private_key_hex or hex(random.getrandbits(256))[2:]
            self.address = f"ADDR_{self.private_key_hex[:8]}"

    def get_address(self):
        return self.address
    
    def get_private_key(self):
        return self.private_key_hex

###############################################################################
# ŁĄCZENIE Z WĘZŁEM (HTTP) - TYLKO TRYB ONLINE
###############################################################################

class ChainConnector:
    """
    Łączy się z węzłem, który nasłuchuje na /balance, /transaction, /stake, /faucet.
    """
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")

    def get_balance(self, address):
        url = f"{self.base_url}/balance?address={address}"
        resp = requests.get(url)
        data = resp.json()
        return data.get("balance", 0)

   # def get_stake(self, address):
   #     # Zakładamy, że węzeł obsługuje /stake_info?address=...
   #     # Jeśli tego nie ma, możesz zwracać 0 albo dodać endpoint
   #     url = f"{self.base_url}/stake_info?address={address}"
   #     resp = requests.get(url)
   #     data = resp.json()
   #     return data.get("stake", 0)

    def send_transaction(self, from_address, to_address, amount):
        # W realnym systemie transakcja powinna być podpisywana kluczem prywatnym
        tx_data = {
            "public_key_hex": from_address,
            "receiver": to_address,
            "amount": amount,
            "signature": "FAKE_SIGNATURE"
        }
        url = f"{self.base_url}/transaction"
        resp = requests.post(url, json=tx_data)
        if resp.status_code == 200:
            return True, resp.json().get("status", "OK")
        else:
            return False, resp.json().get("status", "Error")

    def stake_tokens(self, address, amount):
        staker_data = {
            "public_key_hex": address,
            "amount": amount
        }
        url = f"{self.base_url}/stake"
        resp = requests.post(url, json=staker_data)
        if resp.status_code == 200:
            return True, resp.json().get("status", "OK")
        else:
            return False, resp.json().get("status", "Error")

    def faucet(self, address, amount=100):
        # O ile węzeł ma endpoint /faucet
        data = {"address": address, "amount": amount}
        url = f"{self.base_url}/faucet"
        resp = requests.post(url, json=data)
        if resp.status_code == 200:
            return True, resp.json()
        else:
            return False, resp.json()

###############################################################################
# GŁÓWNE GUI (Portfel)
###############################################################################

class WalletGUI:
    def __init__(self):
        # Zawsze tryb online
        self.blockchain = ChainConnector("http://127.0.0.1:8000")

        self.wallet = Wallet()  # Generujemy portfel przy starcie

        self.window = tk.Tk()
        self.window.title("Simple Wallet GUI (Online Mode)")

        # Sekcja Portfel
        frame_wallet = tk.LabelFrame(self.window, text="Portfel")
        frame_wallet.pack(padx=10, pady=10, fill="x")

        tk.Label(frame_wallet, text="Twój adres:").pack(anchor="w")
        self.label_address = tk.Label(frame_wallet, text=self.wallet.get_address())
        self.label_address.pack(anchor="w", padx=10)

        tk.Label(frame_wallet, text="Twój klucz prywatny:").pack(anchor="w")
        self.label_privkey = tk.Label(frame_wallet, text=self.wallet.get_private_key())
        self.label_privkey.pack(anchor="w", padx=10)

        tk.Button(frame_wallet, text="Importuj klucz prywatny", command=self.import_private_key).pack(pady=5)

        # Sekcja Stan konta
        frame_balance = tk.LabelFrame(self.window, text="Stan konta")
        frame_balance.pack(padx=10, pady=10, fill="x")

        self.label_balance = tk.Label(frame_balance, text="")
        self.label_balance.pack(anchor="w", padx=10)
        self.label_stake = tk.Label(frame_balance, text="")
        self.label_stake.pack(anchor="w", padx=10)

        tk.Button(frame_balance, text="Odśwież", command=self.refresh_balance).pack(pady=5)

        # Sekcja Wyślij
        frame_send = tk.LabelFrame(self.window, text="Wyślij tokeny")
        frame_send.pack(padx=10, pady=10, fill="x")

        tk.Label(frame_send, text="Adres docelowy:").pack(anchor="w")
        self.entry_send_to = tk.Entry(frame_send, width=40)
        self.entry_send_to.pack(anchor="w", padx=10)

        tk.Label(frame_send, text="Kwota:").pack(anchor="w")
        self.entry_amount = tk.Entry(frame_send, width=20)
        self.entry_amount.pack(anchor="w", padx=10)

        tk.Button(frame_send, text="Wyślij", command=self.send_tokens).pack(pady=5)

        # Sekcja Stake
        frame_stake = tk.LabelFrame(self.window, text="Stake")
        frame_stake.pack(padx=10, pady=10, fill="x")

        tk.Label(frame_stake, text="Kwota do zablokowania:").pack(anchor="w")
        self.entry_stake_amount = tk.Entry(frame_stake, width=20)
        self.entry_stake_amount.pack(anchor="w", padx=10)

        tk.Button(frame_stake, text="Stake", command=self.stake_tokens).pack(pady=5)

        # Sekcja Faucet
        frame_faucet = tk.LabelFrame(self.window, text="Faucet")
        frame_faucet.pack(padx=10, pady=10, fill="x")

        tk.Button(frame_faucet, text="Dodaj 100 tokenów do portfela", command=self.use_faucet).pack(pady=5)

        # Kopiowanie klucza
        tk.Button(frame_wallet, text="Kopiuj klucz prywatny", command=self.copy_private_key).pack(pady=5)

        # Na koniec odświeżamy wyświetlane saldo
        self.refresh_balance()

    def import_private_key(self):
        priv_hex = simpledialog.askstring("Import klucza", "Podaj klucz prywatny (hex):")
        if not priv_hex:
            return
        self.wallet = Wallet(priv_hex)
        self.label_address.config(text=self.wallet.get_address())
        self.label_privkey.config(text=self.wallet.get_private_key())
        self.refresh_balance()

    def refresh_balance(self):
        addr = self.wallet.get_address()
        balance = self.blockchain.get_balance(addr)
      #  stake = self.blockchain.get_stake(addr)  # w get_stake() łączymy się do /stake_info
        self.label_balance.config(text=f"Saldo: {balance}")
       # self.label_stake.config(text=f"Stake: {stake}")

    def send_tokens(self):
        addr_from = self.wallet.get_address()
        addr_to = self.entry_send_to.get().strip()
        try:
            amount = float(self.entry_amount.get().strip())
        except ValueError:
            messagebox.showerror("Błąd", "Kwota musi być liczbą.")
            return

        success, info = self.blockchain.send_transaction(addr_from, addr_to, amount)
        if success:
            messagebox.showinfo("Sukces", info)
        else:
            messagebox.showerror("Błąd", info)
        self.refresh_balance()

    def stake_tokens(self):
        addr = self.wallet.get_address()
        try:
            amount = float(self.entry_stake_amount.get().strip())
        except ValueError:
            messagebox.showerror("Błąd", "Kwota musi być liczbą.")
            return

        success, info = self.blockchain.stake_tokens(addr, amount)
        if success:
            messagebox.showinfo("Sukces", info)
        else:
            messagebox.showerror("Błąd", info)
        self.refresh_balance()

    def use_faucet(self):
        """
        Wołamy /faucet z parametrem address, np. 100 tokenów.
        """
        addr = self.wallet.get_address()
        ok, resp = self.blockchain.faucet(addr, 100)
        if ok:
            messagebox.showinfo("Faucet", f"{resp}")
        else:
            messagebox.showerror("Faucet error", f"{resp}")
        self.refresh_balance()

    def copy_private_key(self):
        pk = self.wallet.get_private_key()
        self.window.clipboard_clear()
        self.window.clipboard_append(pk)
        self.window.update()
        messagebox.showinfo("Kopiowanie", "Klucz prywatny został skopiowany do schowka.")

    def run(self):
        self.window.mainloop()

###############################################################################
# Start
###############################################################################

if __name__ == "__main__":
    # Uruchamiamy zawsze w trybie online
    gui = WalletGUI()
    gui.run()
