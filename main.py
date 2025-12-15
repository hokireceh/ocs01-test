
#!/usr/bin/env python3
import json, base64, hashlib, time, sys, re, random, os, shutil, asyncio, aiohttp
from datetime import datetime
import logging
import secrets
import ssl
import signal

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('multi_wallet.log'),
        logging.StreamHandler()
    ]
)

try:
    import nacl.signing
except ImportError:
    print("Error: PyNaCl library tidak ditemukan. Install dengan: pip install PyNaCl")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Error: Cryptography library tidak ditemukan. Install dengan: pip install cryptography")
    sys.exit(1)

try:
    import colorama
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    print("Error: Colorama library tidak ditemukan. Install dengan: pip install colorama")
    sys.exit(1)

# Color definitions
c = {
    'r': Style.RESET_ALL, 
    'b': Fore.BLUE, 
    'c': Fore.CYAN, 
    'g': Fore.GREEN, 
    'y': Fore.YELLOW, 
    'R': Fore.RED, 
    'B': Style.BRIGHT, 
    'bg': Back.BLUE, 
    'bgr': Back.RED, 
    'bgg': Back.GREEN, 
    'w': Fore.WHITE
}

# Global variables
wallets = []
current_wallet_idx = 0
μ = 1_000_000
session = None
transaction_log = []
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")

async def init_session():
    """Initialize or get existing aiohttp session"""
    global session
    if not session:
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context, force_close=True)
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=connector,
            json_serialize=json.dumps
        )
    return session

async def close_session():
    """Properly close the aiohttp session"""
    global session
    if session:
        await session.close()
        session = None

class Wallet:
    def __init__(self, wallet_data):
        self.priv = wallet_data.get('priv')
        self.addr = wallet_data.get('addr')
        self.rpc = wallet_data.get('rpc', 'https://octra.network')
        self.balance = 0.0
        self.encrypted_balance = 0.0
        self.total_balance = 0.0
        self.nonce = 0
        self.last_update = 0
        self.status = "Belum Dicek"
        self.pending_txs = 0
        self.pending_private_transfers = 0

        # For demo purposes, add some sample data
        if "--demo" in sys.argv:
            import random
            self.balance = round(random.uniform(650.0, 700.0), 6)
            self.encrypted_balance = round(random.uniform(50.0, 150.0), 6)
            self.total_balance = self.balance + self.encrypted_balance
            self.nonce = random.randint(80, 90)
            self.status = random.choice(["Aktif", "Aktif", "Error Koneksi"])

        try:
            # For demo mode, generate valid keys if invalid demo keys provided
            decoded_priv = base64.b64decode(self.priv)
            if len(decoded_priv) != 32:
                # Generate a proper 32-byte key for demo
                import os
                demo_key = os.urandom(32)
                self.sk = nacl.signing.SigningKey(demo_key)
            else:
                self.sk = nacl.signing.SigningKey(decoded_priv)

            self.pub = base64.b64encode(self.sk.verify_key.encode()).decode()
            self.valid = True
        except Exception as e:
            logging.error(f"Error membuat signing key untuk {self.addr}: {e}")
            self.valid = False
            self.status = "Error Key"

def cls():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def sz():
    """Get terminal size"""
    return shutil.get_terminal_size((120, 30))

def load_wallets():
    """Load wallets from wallets.json file"""
    global wallets
    try:
        if not os.path.exists('wallets.json'):
            print(f"{c['R']}File wallets.json tidak ditemukan!")
            print(f"{c['y']}Silakan buat file wallets.json dengan format yang benar.")
            print(f"{c['y']}Contoh file tersedia di wallets.json.example")
            return False

        with open('wallets.json', 'r') as f:
            wallet_data = json.load(f)

        if not isinstance(wallet_data, list):
            print(f"{c['R']}Format wallets.json salah! Harus berupa array dari wallet objects.")
            return False

        wallets = [Wallet(wd) for wd in wallet_data]
        valid_wallets = [w for w in wallets if w.valid]

        if not valid_wallets:
            print(f"{c['R']}Tidak ada wallet yang valid ditemukan!")
            return False

        print(f"{c['g']}Berhasil memuat {len(valid_wallets)} wallet dari {len(wallets)} total.")
        return True

    except json.JSONDecodeError:
        print(f"{c['R']}Error: File wallets.json tidak valid JSON!")
        return False
    except Exception as e:
        print(f"{c['R']}Error memuat wallets: {e}")
        return False

# Encryption functions for private balance
def derive_encryption_key(privkey_b64):
    privkey_bytes = base64.b64decode(privkey_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + privkey_bytes).digest()[:32]

def encrypt_client_balance(balance, privkey_b64):
    key = derive_encryption_key(privkey_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def decrypt_client_balance(encrypted_data, privkey_b64):
    if encrypted_data == "0" or not encrypted_data:
        return 0

    if not encrypted_data.startswith("v2|"):
        # Handle legacy v1 format if needed
        return 0

    try:
        b64_data = encrypted_data[3:]
        raw = base64.b64decode(b64_data)

        if len(raw) < 28:
            return 0

        nonce = raw[:12]
        ciphertext = raw[12:]

        key = derive_encryption_key(privkey_b64)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return 0

def derive_shared_secret_for_claim(my_privkey_b64, ephemeral_pubkey_b64):
    sk = nacl.signing.SigningKey(base64.b64decode(my_privkey_b64))
    my_pubkey_bytes = sk.verify_key.encode()
    eph_pub_bytes = base64.b64decode(ephemeral_pubkey_b64)

    if eph_pub_bytes < my_pubkey_bytes:
        smaller, larger = eph_pub_bytes, my_pubkey_bytes
    else:
        smaller, larger = my_pubkey_bytes, eph_pub_bytes

    combined = smaller + larger
    round1 = hashlib.sha256(combined).digest()
    round2 = hashlib.sha256(round1 + b"OCTRA_SYMMETRIC_V1").digest()
    return round2[:32]

def decrypt_private_amount(encrypted_data, shared_secret):
    if not encrypted_data or not encrypted_data.startswith("v2|"):
        return None

    try:
        raw = base64.b64decode(encrypted_data[3:])
        if len(raw) < 28:
            return None

        nonce = raw[:12]
        ciphertext = raw[12:]

        aesgcm = AESGCM(shared_secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return int(plaintext.decode())
    except:
        return None

async def req(method, path, data=None, timeout=10, rpc_url=None):
    """Make HTTP request to OCTra network"""
    await init_session()

    try:
        url = f"{rpc_url or 'https://octra.network'}{path}"

        kwargs = {'timeout': aiohttp.ClientTimeout(total=timeout)}
        if method == 'POST' and data:
            kwargs['json'] = data

        async with getattr(session, method.lower())(url, **kwargs) as resp:
            text = await resp.text()
            try:
                j = json.loads(text) if text else None
            except:
                j = None
            return resp.status, text, j
    except asyncio.TimeoutError:
        return 0, "timeout", None
    except Exception as e:
        return 0, str(e), None

async def req_private(wallet, path, method='GET', data=None):
    """Make private request with wallet's private key"""
    await init_session()
    
    headers = {"X-Private-Key": wallet.priv}
    try:
        url = f"{wallet.rpc}{path}"

        kwargs = {'headers': headers}
        if method == 'POST' and data:
            kwargs['json'] = data

        async with getattr(session, method.lower())(url, **kwargs) as resp:
            text = await resp.text()

            if resp.status == 200:
                try:
                    return True, json.loads(text) if text.strip() else {}
                except:
                    return False, {"error": "Invalid JSON response"}
            else:
                return False, {"error": f"HTTP {resp.status}"}

    except Exception as e:
        return False, {"error": str(e)}

async def get_encrypted_balance(wallet):
    """Get encrypted balance for wallet"""
    ok, result = await req_private(wallet, f"/view_encrypted_balance/{wallet.addr}")

    if ok:
        try:
            return {
                "public": float(result.get("public_balance", "0").split()[0]),
                "public_raw": int(result.get("public_balance_raw", "0")),
                "encrypted": float(result.get("encrypted_balance", "0").split()[0]),
                "encrypted_raw": int(result.get("encrypted_balance_raw", "0")),
                "total": float(result.get("total_balance", "0").split()[0])
            }
        except:
            return None
    else:
        return None

async def get_pending_transfers(wallet):
    """Get pending private transfers for wallet"""
    ok, result = await req_private(wallet, f"/pending_private_transfers?address={wallet.addr}")

    if ok:
        transfers = result.get("pending_transfers", [])
        return transfers
    else:
        return []

async def encrypt_balance(wallet, amount):
    """Encrypt balance for wallet"""
    enc_data = await get_encrypted_balance(wallet)
    if not enc_data:
        return False, {"error": "cannot get balance"}

    current_encrypted_raw = enc_data['encrypted_raw']
    new_encrypted_raw = current_encrypted_raw + int(amount * μ)

    encrypted_value = encrypt_client_balance(new_encrypted_raw, wallet.priv)

    data = {
        "address": wallet.addr,
        "amount": str(int(amount * μ)),
        "private_key": wallet.priv,
        "encrypted_data": encrypted_value
    }

    s, t, j = await req('POST', '/encrypt_balance', data, rpc_url=wallet.rpc)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def create_private_transfer(wallet, to_addr, amount):
    """Create private transfer"""
    addr_info = await get_address_info(wallet, to_addr)
    if not addr_info or not addr_info.get("has_public_key"):
        return False, {"error": "Recipient has no public key"}

    to_public_key = await get_public_key(wallet, to_addr)
    if not to_public_key:
        return False, {"error": "Cannot get recipient public key"}

    data = {
        "from": wallet.addr,
        "to": to_addr,
        "amount": str(int(amount * μ)),
        "from_private_key": wallet.priv,
        "to_public_key": to_public_key
    }

    s, t, j = await req('POST', '/private_transfer', data, rpc_url=wallet.rpc)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def get_address_info(wallet, address):
    """Get address info"""
    s, t, j = await req('GET', f'/address/{address}', rpc_url=wallet.rpc)
    if s == 200:
        return j
    return None

async def get_public_key(wallet, address):
    """Get public key for address"""
    s, t, j = await req('GET', f'/public_key/{address}', rpc_url=wallet.rpc)
    if s == 200:
        return j.get("public_key")
    return None

async def claim_private_transfer(wallet, transfer_id):
    """Claim private transfer"""
    data = {
        "recipient_address": wallet.addr,
        "private_key": wallet.priv,
        "transfer_id": transfer_id
    }

    s, t, j = await req('POST', '/claim_private_transfer', data, rpc_url=wallet.rpc)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def update_wallet_status(wallet):
    """Update wallet balance and nonce"""
    now = time.time()

    # Skip if updated recently (less than 30 seconds ago)
    if (now - wallet.last_update) < 30:
        return

    try:
        results = await asyncio.gather(
            req('GET', f'/balance/{wallet.addr}', rpc_url=wallet.rpc),
            req('GET', '/staging', timeout=5, rpc_url=wallet.rpc),
            get_encrypted_balance(wallet),
            get_pending_transfers(wallet),
            return_exceptions=True
        )

        # Public balance and nonce
        if isinstance(results[0], Exception):
            s, t, j = 0, str(results[0]), None
        else:
            s, t, j = results[0]

        if s == 200 and j:
            wallet.nonce = int(j.get('nonce', 0))
            wallet.balance = float(j.get('balance', 0))
            wallet.status = "Aktif"
        elif s == 404:
            wallet.nonce = 0
            wallet.balance = 0.0
            wallet.status = "Wallet Baru"
        elif s == 200 and t and not j:
            # Handle plain text response
            try:
                parts = t.strip().split()
                if len(parts) >= 2:
                    wallet.balance = float(parts[0]) if parts[0].replace('.', '').isdigit() else 0.0
                    wallet.nonce = int(parts[1]) if parts[1].isdigit() else 0
                    wallet.status = "Aktif"
            except:
                wallet.status = "Error Format"
        else:
            wallet.status = "Error Koneksi"

        # Check pending transactions
        if isinstance(results[1], Exception):
            s2, _, j2 = 0, None, None
        else:
            s2, _, j2 = results[1]
        if s2 == 200 and j2:
            our_txs = [tx for tx in j2.get('staged_transactions', []) if tx.get('from') == wallet.addr]
            wallet.pending_txs = len(our_txs)
            if our_txs:
                wallet.nonce = max(wallet.nonce, max(int(tx.get('nonce', 0)) for tx in our_txs))

        # Encrypted balance
        if isinstance(results[2], Exception):
            enc_data = None
        else:
            enc_data = results[2]
        if enc_data:
            wallet.encrypted_balance = enc_data['encrypted']
            wallet.total_balance = enc_data['total']
        else:
            wallet.encrypted_balance = 0.0
            wallet.total_balance = wallet.balance

        # Pending private transfers
        if isinstance(results[3], Exception):
            pending_transfers = []
        else:
            pending_transfers = results[3]
        wallet.pending_private_transfers = len(pending_transfers) if pending_transfers else 0

        wallet.last_update = now

    except Exception as e:
        wallet.status = f"Error: {str(e)[:20]}"
        logging.error(f"Error updating wallet {wallet.addr}: {e}")

def create_transaction(wallet, to_addr, amount, message=None):
    """Create a signed transaction"""
    try:
        tx = {
            "from": wallet.addr,
            "to_": to_addr,
            "amount": str(int(amount * μ)),
            "nonce": int(wallet.nonce + 1),
            "ou": "1" if amount < 1000 else "3",
            "timestamp": time.time() + random.random() * 0.01
        }

        if message:
            tx["message"] = message

        # Create transaction block for signing (exclude message)
        block_data = json.dumps({k: v for k, v in tx.items() if k != "message"}, separators=(",", ":"))

        # Sign transaction
        signature = base64.b64encode(wallet.sk.sign(block_data.encode()).signature).decode()
        tx.update(signature=signature, public_key=wallet.pub)

        # Create transaction hash
        tx_hash = hashlib.sha256(block_data.encode()).hexdigest()

        return tx, tx_hash

    except Exception as e:
        logging.error(f"Error creating transaction for {wallet.addr}: {e}")
        return None, None

async def send_transaction(wallet, tx):
    """Send transaction to network"""
    try:
        start_time = time.time()
        status, text, json_resp = await req('POST', '/send-tx', tx, rpc_url=wallet.rpc)
        elapsed = time.time() - start_time

        if status == 200:
            if json_resp and json_resp.get('status') == 'accepted':
                tx_hash = json_resp.get('tx_hash', '')
                return True, tx_hash, elapsed, json_resp
            elif text.lower().startswith('ok'):
                tx_hash = text.split()[-1] if len(text.split()) > 1 else ''
                return True, tx_hash, elapsed, None

        error_msg = json.dumps(json_resp) if json_resp else text
        return False, error_msg, elapsed, json_resp

    except Exception as e:
        logging.error(f"Error sending transaction from {wallet.addr}: {e}")
        return False, str(e), 0, None

def display_header():
    """Display application header"""
    cr = sz()
    current_time = datetime.now().strftime('%H:%M:%S')
    title = f" OCTra Multi-Wallet Advanced By Hokireceh v2.0 │ {current_time} "

    print(f"{c['B']}{c['bg']}{' ' * cr[0]}")
    print(f"{c['B']}{c['bg']}{title.center(cr[0])}")
    print(f"{c['B']}{c['bg']}{' ' * cr[0]}{c['r']}")
    print()

def display_wallet_table():
    """Display wallet status table with enhanced info"""
    print(f"{c['B']}{c['c']}═══ STATUS WALLET ADVANCED ═════════════════════════════════════════════════════════════════")
    print(f"{c['w']}{'No':<3} {'Alamat':<45} {'Public':<12} {'Encrypted':<12} {'Total':<12} {'Nonce':<6} {'Pend':<5} {'PvtT':<5} {'Status':<15}")
    print(f"{c['c']}{'─'*3} {'─'*45} {'─'*12} {'─'*12} {'─'*12} {'─'*6} {'─'*5} {'─'*5} {'─'*15}")

    total_public = 0
    total_encrypted = 0
    total_balance = 0
    active_wallets = 0

    for i, wallet in enumerate(wallets):
        if not wallet.valid:
            continue

        # Color coding for different statuses
        if wallet.status == "Aktif":
            status_color = c['g']
            active_wallets += 1
        elif wallet.status == "Wallet Baru":
            status_color = c['y']
            active_wallets += 1
        elif "Error" in wallet.status:
            status_color = c['R']
        else:
            status_color = c['w']

        # Mark current wallet
        marker = "►" if i == current_wallet_idx else " "

        # Format balances
        public_str = f"{wallet.balance:.6f}" if wallet.balance > 0 else "0.000000"
        encrypted_str = f"{wallet.encrypted_balance:.6f}" if wallet.encrypted_balance > 0 else "0.000000"
        total_str = f"{wallet.total_balance:.6f}" if wallet.total_balance > 0 else "0.000000"

        total_public += wallet.balance
        total_encrypted += wallet.encrypted_balance
        total_balance += wallet.total_balance

        # Pending indicators
        pending_str = f"{wallet.pending_txs}" if wallet.pending_txs > 0 else "-"
        pending_color = c['y'] if wallet.pending_txs > 0 else c['w']

        pvt_transfer_str = f"{wallet.pending_private_transfers}" if wallet.pending_private_transfers > 0 else "-"
        pvt_transfer_color = c['g'] if wallet.pending_private_transfers > 0 else c['w']

        print(f"{c['w']}{marker}{i+1:<2} {wallet.addr:<45} {c['g']}{public_str:<12} "
              f"{c['y']}{encrypted_str:<12} {c['B']}{c['g']}{total_str:<12} "
              f"{c['w']}{wallet.nonce:<6} {pending_color}{pending_str:<5} "
              f"{pvt_transfer_color}{pvt_transfer_str:<5} {status_color}{wallet.status:<15}")

    print(f"{c['c']}{'─'*120}")
    print(f"{c['B']}{c['g']}Total Public: {total_public:.6f} OCT │ "
          f"Total Encrypted: {total_encrypted:.6f} OCT │ "
          f"Grand Total: {total_balance:.6f} OCT")
    print(f"{c['B']}{c['g']}Wallet Aktif: {active_wallets}/{len([w for w in wallets if w.valid])}")
    print()

def display_transaction_log():
    """Display recent transaction log with OCTra scanner links"""
    if not transaction_log:
        return

    print(f"{c['B']}{c['c']}═══ LOG TRANSAKSI TERBARU ═══════════════════════════════════════════════════════════════════")
    print(f"{c['w']}{'Waktu':<8} {'Dari':<20} {'Ke':<20} {'Amount':<8} {'Type':<8} {'Status':<12} {'Hash':<20}")
    print(f"{c['c']}{'─'*8} {'─'*20} {'─'*20} {'─'*8} {'─'*8} {'─'*12} {'─'*20}")

    # Show last 15 transactions
    recent_logs = transaction_log[-15:]
    for log in recent_logs:
        status_color = c['g'] if log['success'] else c['R']
        status_text = "Berhasil" if log['success'] else "Gagal"

        tx_type = log.get('type', 'Public')
        type_color = c['y'] if tx_type == 'Private' else c['w']

        print(f"{c['w']}{log['time']:<8} {log['from_addr'][-20:]:<20} {log['to_addr'][-20:]:<20} "
              f"{c['y']}{log['amount']:<8} {type_color}{tx_type:<8} "
              f"{status_color}{status_text:<12} {c['c']}{log['hash'][:20]:<20}")

        # Show OCTra scanner link for successful transactions with valid hash
        if log['success'] and log['hash'] and log['hash'] not in ['Error', 'Saldo tidak cukup'] and not log['hash'].startswith('demo_'):
            print(f"{c['w']}     🔗 Scanner: {c['b']}https://octrascan.io/tx/{log['hash']}")

    print()
    print(f"{c['B']}{c['c']}💡 Tip: Copy link scanner di atas untuk melihat detail transaksi di blockchain explorer")
    print()

async def manual_send():
    """Manual send transaction - choose wallet and recipient address"""
    cls()
    display_header()
    
    valid_wallets = [w for w in wallets if w.valid]
    if not valid_wallets:
        print(f"{c['R']}Tidak ada wallet yang valid untuk diproses!")
        input(f"{c['y']}Tekan Enter untuk melanjutkan...")
        return

    # Show wallet list
    print(f"{c['B']}{c['c']}═══ PILIH WALLET PENGIRIM ═════════════════════════════════════════════════════════════════")
    for i, w in enumerate(valid_wallets):
        print(f"{c['w']}[{i+1}] {w.addr} (Public: {w.balance:.6f} | Encrypted: {w.encrypted_balance:.6f})")
    
    print(f"{c['c']}{'═'*95}")
    
    try:
        wallet_choice = input(f"{c['B']}{c['y']}Pilih wallet (nomor): {c['w']}").strip()
        wallet_idx = int(wallet_choice) - 1
        
        if wallet_idx < 0 or wallet_idx >= len(valid_wallets):
            print(f"{c['R']}❌ Pilihan tidak valid!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        source_wallet = valid_wallets[wallet_idx]
        
        # Get recipient address
        print(f"\n{c['y']}Alamat pengirim: {c['g']}{source_wallet.addr}")
        recipient = input(f"{c['B']}{c['y']}Masukkan alamat penerima (atau 'batal'): {c['w']}").strip()
        
        if recipient.lower() == 'batal':
            print(f"{c['y']}Dibatalkan.")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        # Validate address format
        if not b58.match(recipient):
            print(f"{c['R']}❌ Format alamat tidak valid!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        if recipient == source_wallet.addr:
            print(f"{c['R']}❌ Tidak bisa mengirim ke alamat yang sama!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        # Get transaction type
        print(f"\n{c['B']}{c['c']}═══ PILIH TIPE TRANSAKSI ═════════════════════════════════════════════════════════════════")
        print(f"{c['w']}[1] 💰 Public Transaction (dari saldo public)")
        print(f"{c['w']}[2] 🔒 Private Transaction (dari saldo encrypted)")
        print(f"{c['w']}[3] 🔐 Encrypt Balance (ubah public menjadi encrypted)")
        print(f"{c['w']}[4] 🔓 Decrypt Balance (ubah encrypted menjadi public)")
        print(f"{c['c']}{'═'*95}")
        
        tx_type_choice = input(f"{c['B']}{c['y']}Pilih tipe (1-4): {c['w']}").strip()
        
        if tx_type_choice == '1':
            tx_type = 'Public'
            max_amount = source_wallet.balance
        elif tx_type_choice == '2':
            tx_type = 'Private'
            max_amount = source_wallet.encrypted_balance
        elif tx_type_choice == '3':
            tx_type = 'Encrypt'
            max_amount = source_wallet.balance
        elif tx_type_choice == '4':
            tx_type = 'Decrypt'
            max_amount = source_wallet.encrypted_balance
        else:
            print(f"{c['R']}❌ Pilihan tidak valid!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        # Get amount
        print(f"\n{c['y']}Available: {max_amount:.6f} OCT")
        amount_str = input(f"{c['B']}{c['y']}Masukkan jumlah (atau 'batal'): {c['w']}").strip()
        
        if amount_str.lower() == 'batal':
            print(f"{c['y']}Dibatalkan.")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        try:
            amount = float(amount_str)
        except ValueError:
            print(f"{c['R']}❌ Jumlah tidak valid!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        if amount <= 0:
            print(f"{c['R']}❌ Jumlah harus lebih dari 0!")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        if amount > max_amount:
            print(f"{c['R']}❌ Saldo tidak mencukupi! (Max: {max_amount:.6f})")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        # Confirmation
        print(f"\n{c['B']}{c['c']}═══ KONFIRMASI TRANSAKSI ═════════════════════════════════════════════════════════════════")
        print(f"{c['w']}Dari:     {c['g']}{source_wallet.addr}")
        print(f"{c['w']}Ke:       {c['g']}{recipient}")
        print(f"{c['w']}Tipe:     {c['y']}{tx_type}")
        print(f"{c['w']}Jumlah:   {c['B']}{c['g']}{amount:.6f} OCT")
        print(f"{c['c']}{'═'*95}")
        
        confirm = input(f"{c['B']}{c['y']}Lanjutkan? (yes/no): {c['w']}").strip().lower()
        
        if confirm != 'yes':
            print(f"{c['y']}Dibatalkan.")
            input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            return
        
        # Update wallet status first
        print(f"\n{c['y']}⏳ Mengupdate status wallet...")
        await update_wallet_status(source_wallet)
        
        # Execute transaction
        print(f"{c['y']}⏳ Memproses transaksi {tx_type}...")
        
        success = False
        result = ""
        response = None
        
        try:
            if tx_type == 'Public':
                success, result, response = await send_public_transaction(source_wallet, recipient, amount)
            elif tx_type == 'Private':
                success, result, response = await send_private_transaction(source_wallet, recipient, amount)
            elif tx_type == 'Encrypt':
                success, response = await encrypt_balance(source_wallet, amount)
                result = response.get('tx_hash', 'unknown') if isinstance(response, dict) else str(response)
            elif tx_type == 'Decrypt':
                success, response = await decrypt_balance(source_wallet, amount)
                result = response.get('tx_hash', 'unknown') if isinstance(response, dict) else str(response)
        except Exception as e:
            success = False
            result = str(e)
            response = None
        
        # Log transaction
        log_entry = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'from_addr': source_wallet.addr,
            'to_addr': recipient if tx_type in ['Public', 'Private'] else 'Self',
            'amount': str(amount),
            'type': tx_type,
            'success': success,
            'hash': result if success else 'Error',
            'response': str(response) if response else result
        }
        transaction_log.append(log_entry)
        
        # Show result
        print(f"\n{c['B']}{c['c']}═══ HASIL TRANSAKSI ═════════════════════════════════════════════════════════════════════")
        if success:
            print(f"{c['g']}✅ Transaksi {tx_type} BERHASIL!")
            print(f"{c['w']}Hash: {c['g']}{result}")
            if result and not result.startswith(('Error', 'encrypt_', 'decrypt_', 'unknown')):
                print(f"{c['b']}🔗 Scanner: https://octrascan.io/tx/{result}")
        else:
            print(f"{c['R']}❌ Transaksi {tx_type} GAGAL!")
            print(f"{c['R']}Error: {result}")
        
        logging.info(f"Manual Send - Wallet {source_wallet.addr}: {tx_type} {'SUCCESS' if success else 'FAILED'} - {result}")
        
        input(f"\n{c['y']}Tekan Enter untuk melanjutkan...")
        
    except ValueError:
        print(f"{c['R']}❌ Input tidak valid!")
        input(f"{c['y']}Tekan Enter untuk melanjutkan...")
    except Exception as e:
        print(f"{c['R']}💥 Error: {e}")
        logging.error(f"Manual send error: {e}")
        input(f"{c['y']}Tekan Enter untuk melanjutkan...")

async def send_public_transaction(wallet, to_addr, amount):
    """Send public transaction"""
    tx, tx_hash = create_transaction(wallet, to_addr, amount)
    if tx and tx_hash:
        success, result, elapsed, response = await send_transaction(wallet, tx)
        return success, result, response
    else:
        return False, "Transaction creation failed", None

async def send_private_transaction(wallet, to_addr, amount):
    """Send private transaction"""
    try:
        success, result = await create_private_transfer(wallet, to_addr, amount)
        if success:
            return True, result.get('tx_hash', 'unknown'), result
        else:
            return False, result.get('error', 'unknown error'), result
    except Exception as e:
        return False, str(e), None

async def auto_claim_transfers(wallet):
    """Auto-claim pending private transfers"""
    try:
        transfers = await get_pending_transfers(wallet)
        claimed_count = 0

        for transfer in transfers:
            transfer_id = transfer.get('id')
            if transfer_id:
                success, result = await claim_private_transfer(wallet, transfer_id)
                if success:
                    claimed_count += 1
                    print(f"{c['g']}✅ Claimed transfer #{transfer_id}")
                else:
                    print(f"{c['R']}❌ Failed to claim transfer #{transfer_id}: {result.get('error', 'unknown')}")

                await asyncio.sleep(1)  # Brief delay between claims

        if claimed_count > 0:
            print(f"{c['g']}🎉 Successfully claimed {claimed_count} private transfers!")
            # Force update wallet status after claiming
            wallet.last_update = 0
            await update_wallet_status(wallet)

    except Exception as e:
        print(f"{c['R']}Error auto-claiming transfers: {e}")

async def update_all_wallets():
    """Update status for all wallets"""
    print(f"{c['y']}🔄 Mengupdate status semua wallet dengan fitur private...")

    valid_wallets = [w for w in wallets if w.valid]

    # Update wallets in batches to avoid overwhelming the network
    batch_size = 3
    for i in range(0, len(valid_wallets), batch_size):
        batch = valid_wallets[i:i+batch_size]
        await asyncio.gather(*[update_wallet_status(w) for w in batch])
        if i + batch_size < len(valid_wallets):
            await asyncio.sleep(1)  # Brief pause between batches

def show_menu():
    """Display main menu with new options"""
    print(f"{c['B']}{c['c']}═══ MENU UTAMA ADVANCED ═══════════════════════════════════════════════════════════════════")
    print(f"{c['w']}[1] 💸 Kirim Transaksi Manual (Pilih Wallet & Alamat)")
    print(f"{c['w']}[2] 📤 Multi-Send (Batch Transactions ke Multiple Alamat)")
    print(f"{c['w']}[3] 🔄 Update Status Semua Wallet")
    print(f"{c['w']}[4] 📊 Tampilkan Status & Detail Wallet")
    print(f"{c['w']}[5] 📝 Tampilkan Log Transaksi Lengkap")
    print(f"{c['w']}[6] 🔒 Auto-Claim All Private Transfers")
    print(f"{c['w']}[7] 💰 Auto-Encrypt Manual Amount")
    print(f"{c['w']}[8] 🔓 Auto-Decrypt All Balances")
    print(f"{c['w']}[9] 💾 Export Wallet Keys (Backup)")
    print(f"{c['w']}[A] 🧹 Clear Transaction History")
    print(f"{c['w']}[B] 🔍 Cek Transaksi di OCTra Scanner")
    print(f"{c['w']}[C] 🔄 Reload Wallet dari File")
    print(f"{c['w']}[0] 🚪 Keluar")
    print(f"{c['c']}{'═'*95}")

async def auto_claim_all_transfers():
    """Auto-claim transfers for all wallets"""
    print(f"{c['y']}🎁 Auto-claiming private transfers untuk semua wallet...")

    valid_wallets = [w for w in wallets if w.valid]
    total_claimed = 0

    for wallet in valid_wallets:
        print(f"{c['c']}Checking wallet: {wallet.addr[:25]}...")
        await update_wallet_status(wallet)

        if wallet.pending_private_transfers > 0:
            print(f"{c['y']}Found {wallet.pending_private_transfers} pending transfers")
            await auto_claim_transfers(wallet)
            total_claimed += wallet.pending_private_transfers

    print(f"{c['g']}✅ Total {total_claimed} transfers di-claim dari semua wallet!")

async def decrypt_balance(wallet, amount):
    """Decrypt balance for wallet"""
    enc_data = await get_encrypted_balance(wallet)
    if not enc_data:
        return False, {"error": "cannot get balance"}

    current_encrypted_raw = enc_data['encrypted_raw']

    if current_encrypted_raw < int(amount * μ):
        return False, {"error": "insufficient encrypted balance"}

    # Calculate new encrypted balance after decryption
    new_encrypted_raw = current_encrypted_raw - int(amount * μ)

    # Encrypt the new balance
    encrypted_value = encrypt_client_balance(new_encrypted_raw, wallet.priv)

    data = {
        "address": wallet.addr,
        "amount": str(int(amount * μ)),
        "private_key": wallet.priv,
        "encrypted_data": encrypted_value
    }

    s, t, j = await req('POST', '/decrypt_balance', data, rpc_url=wallet.rpc)
    if s == 200:
        return True, j
    else:
        return False, {"error": j.get("error", t) if j else t}

async def auto_encrypt_balances():
    """Auto-encrypt manual amounts from public balances"""
    print(f"\n{c['B']}{c['c']}═══ ENCRYPT BALANCE MANUAL ═══════════════════════════════════════════════════════")
    
    valid_wallets = [w for w in wallets if w.valid]
    
    # Show wallet list with balances
    print(f"{c['w']}Pilih wallet yang ingin di-encrypt:")
    for i, wallet in enumerate(valid_wallets):
        await update_wallet_status(wallet)
        print(f"{c['g']}{i+1}. {wallet.addr[:35]} - Public: {wallet.balance:.6f} OCT")
    
    try:
        wallet_choice = input(f"\n{c['B']}{c['y']}Pilih wallet (1-{len(valid_wallets)}) atau 0 untuk semua: {c['w']}")
        wallet_idx = int(wallet_choice) - 1
        
        if wallet_choice == "0":
            wallets_to_process = valid_wallets
        elif 0 <= wallet_idx < len(valid_wallets):
            wallets_to_process = [valid_wallets[wallet_idx]]
        else:
            print(f"{c['R']}Pilihan tidak valid!")
            return
        
        # Ask for amount
        amount_input = input(f"{c['B']}{c['y']}Jumlah OCT yang ingin di-encrypt: {c['w']}")
        encrypt_amount = float(amount_input)
        encrypt_amount = round(encrypt_amount, 6)
        
        if encrypt_amount <= 0:
            print(f"{c['R']}Amount harus lebih dari 0!")
            return
        
        encrypted_count = 0
        for wallet in wallets_to_process:
            await update_wallet_status(wallet)
            
            if wallet.balance >= encrypt_amount + 1.0:  # Keep 1 OCT for fees
                print(f"{c['y']}Encrypting {encrypt_amount:.6f} OCT for {wallet.addr[:25]}...")
                success, result = await encrypt_balance(wallet, encrypt_amount)
                
                if success:
                    print(f"{c['g']}✅ Encrypted {encrypt_amount:.6f} OCT successfully!")
                    encrypted_count += 1
                    wallet.last_update = 0
                else:
                    print(f"{c['R']}❌ Failed to encrypt: {result.get('error', 'unknown')}")
                
                await asyncio.sleep(2)
            else:
                print(f"{c['R']}❌ Saldo tidak cukup untuk {wallet.addr[:25]}! Butuh minimal {encrypt_amount + 1.0:.6f} OCT")
        
        print(f"{c['g']}✅ Successfully encrypted untuk {encrypted_count} wallet(s)!")
        
    except ValueError:
        print(f"{c['R']}Input tidak valid!")
    except Exception as e:
        print(f"{c['R']}Error: {e}")

async def auto_decrypt_balances():
    """Auto-decrypt all encrypted balances to public"""
    print(f"{c['y']}🔓 Auto-decrypting semua encrypted balances...")

    valid_wallets = [w for w in wallets if w.valid]
    decrypted_count = 0

    for wallet in valid_wallets:
        await update_wallet_status(wallet)

        # Decrypt all encrypted balance
        if wallet.encrypted_balance > 0.0:
            decrypt_amount = wallet.encrypted_balance
            decrypt_amount = round(decrypt_amount, 6)

            if decrypt_amount >= 1.0:
                print(f"{c['y']}Decrypting {decrypt_amount:.6f} OCT for {wallet.addr[:25]}...")
                success, result = await decrypt_balance(wallet, decrypt_amount)

                if success:
                    print(f"{c['g']}✅ Decrypted {decrypt_amount:.6f} OCT successfully!")
                    decrypted_count += 1
                    # Update wallet status to reflect change
                    wallet.last_update = 0
                else:
                    print(f"{c['R']}❌ Failed to decrypt: {result.get('error', 'unknown')}")

                await asyncio.sleep(2)  # Brief delay between decryptions

    print(f"{c['g']}✅ Successfully decrypted balances for {decrypted_count} wallets!")

def check_transaction_scanner():
    """Check specific transaction in OCTra scanner"""
    print(f"{c['B']}{c['c']}═══ CEK TRANSAKSI DI OCTRA SCANNER ═══════════════════════════════════════════")
    print(f"{c['w']}Masukkan hash transaksi yang ingin dicek:")
    print(f"{c['y']}Contoh: a1b2c3d4e5f6...")
    print()

    tx_hash = input(f"{c['B']}{c['y']}Hash transaksi: {c['w']}").strip()

    if not tx_hash:
        print(f"{c['R']}❌ Hash transaksi tidak boleh kosong!")
        return

    if len(tx_hash) < 10:
        print(f"{c['R']}❌ Hash transaksi terlalu pendek!")
        return

    scanner_url = f"https://octrascan.io/tx/{tx_hash}"
    print(f"\n{c['g']}✅ Link OCTra Scanner:")
    print(f"{c['b']}{scanner_url}")
    print(f"\n{c['y']}💡 Copy link di atas dan buka di browser untuk melihat detail transaksi")
    print(f"{c['y']}💡 Atau gunakan menu log transaksi untuk melihat link otomatis")

    # Check if hash exists in our transaction log
    matching_logs = [log for log in transaction_log if log['hash'] == tx_hash]
    if matching_logs:
        log = matching_logs[0]
        print(f"\n{c['c']}📋 Ditemukan di log lokal:")
        print(f"{c['w']}   Waktu: {log['time']}")
        print(f"{c['w']}   Dari: {log['from_addr']}")
        print(f"{c['w']}   Ke: {log['to_addr']}")
        print(f"{c['w']}   Amount: {log['amount']} OCT")
        print(f"{c['w']}   Type: {log['type']}")
        print(f"{c['w']}   Status: {'Berhasil' if log['success'] else 'Gagal'}")

async def multi_send():
    """Multi-send: send to multiple addresses from one wallet"""
    cls()
    display_header()
    
    valid_wallets = [w for w in wallets if w.valid]
    if not valid_wallets:
        print(f"{c['R']}Tidak ada wallet yang valid!")
        input(f"{c['y']}Tekan Enter untuk melanjutkan...")
        return

    print(f"{c['B']}{c['c']}═══ PILIH WALLET PENGIRIM ═════════════════════════════════════════════════════════════════")
    for i, w in enumerate(valid_wallets):
        print(f"{c['w']}[{i+1}] {w.addr} (Public: {w.balance:.6f} | Encrypted: {w.encrypted_balance:.6f})")
    
    wallet_idx = int(input(f"{c['B']}{c['y']}Pilih wallet (nomor): {c['w']}").strip()) - 1
    if wallet_idx < 0 or wallet_idx >= len(valid_wallets):
        print(f"{c['R']}❌ Pilihan tidak valid!"); input(f"{c['y']}Tekan Enter..."); return
    
    source_wallet = valid_wallets[wallet_idx]
    
    print(f"\n{c['y']}📍 Wallet: {source_wallet.addr}")
    print(f"{c['y']}💰 Masukkan data dalam format: alamat,jumlah (satu per baris, enter 2x untuk selesai)")
    
    recipients = []
    while True:
        data = input(f"{c['B']}{c['y']}Alamat,Jumlah: {c['w']}").strip()
        if not data:
            break
        try:
            addr, amount_str = data.split(',')
            addr = addr.strip()
            amount = float(amount_str.strip())
            if b58.match(addr) and amount > 0:
                recipients.append((addr, amount))
                print(f"{c['g']}✅ Added: {addr[:25]}... ({amount} OCT)")
            else:
                print(f"{c['R']}❌ Format tidak valid!")
        except:
            print(f"{c['R']}❌ Error parsing!")
    
    if not recipients:
        print(f"{c['R']}❌ Tidak ada penerima!"); input(f"{c['y']}Tekan Enter..."); return
    
    total_amount = sum(amount for _, amount in recipients)
    if total_amount > source_wallet.balance:
        print(f"{c['R']}❌ Saldo tidak cukup! Need {total_amount:.6f}, have {source_wallet.balance:.6f}")
        input(f"{c['y']}Tekan Enter..."); return
    
    print(f"\n{c['B']}{c['c']}═══ KONFIRMASI MULTI-SEND ═════════════════════════════════════════════════════════════════")
    print(f"{c['w']}Total recipient: {len(recipients)}")
    print(f"{c['w']}Total amount: {total_amount:.6f} OCT")
    for addr, amount in recipients[:5]:
        print(f"{c['w']}  • {addr[:30]}... → {amount} OCT")
    if len(recipients) > 5:
        print(f"{c['w']}  • ... dan {len(recipients)-5} lainnya")
    
    if input(f"{c['B']}{c['y']}Lanjutkan? (yes/no): {c['w']}").lower() != 'yes':
        print(f"{c['y']}Dibatalkan."); input(f"{c['y']}Tekan Enter..."); return
    
    await update_wallet_status(source_wallet)
    success_count = 0
    
    print(f"\n{c['y']}⏳ Memproses {len(recipients)} transaksi...")
    for i, (recipient, amount) in enumerate(recipients):
        try:
            success, result, response = await send_public_transaction(source_wallet, recipient, amount)
            log_entry = {
                'time': datetime.now().strftime('%H:%M:%S'),
                'from_addr': source_wallet.addr,
                'to_addr': recipient,
                'amount': str(amount),
                'type': 'Public',
                'success': success,
                'hash': result if success else 'Error',
                'response': str(response) if response else result
            }
            transaction_log.append(log_entry)
            
            if success:
                success_count += 1
                print(f"{c['g']}✅ [{i+1}/{len(recipients)}] Sent to {recipient[:25]}...")
            else:
                print(f"{c['R']}❌ [{i+1}/{len(recipients)}] Failed: {result[:30]}")
        except Exception as e:
            print(f"{c['R']}❌ Error: {str(e)[:50]}")
        await asyncio.sleep(1)
    
    print(f"\n{c['g']}🎉 Multi-send selesai! Sukses: {success_count}/{len(recipients)}")
    input(f"{c['y']}Tekan Enter untuk kembali ke menu utama...")

def export_wallet_keys():
    """Export wallet keys for backup"""
    cls()
    display_header()
    
    valid_wallets = [w for w in wallets if w.valid]
    if not valid_wallets:
        print(f"{c['R']}Tidak ada wallet!"); input(f"{c['y']}Tekan Enter untuk kembali..."); return
    
    print(f"{c['B']}{c['c']}═══ PILIH WALLET UNTUK EXPORT ════════════════════════════════════════════════════════════")
    for i, w in enumerate(valid_wallets):
        print(f"{c['w']}[{i+1}] {w.addr}")
    
    try:
        wallet_idx = int(input(f"{c['B']}{c['y']}Pilih wallet (nomor atau 0 untuk semua): {c['w']}").strip()) - 1
    except:
        input(f"{c['y']}Tekan Enter untuk kembali..."); return
    
    export_data = []
    if wallet_idx == -1:
        export_data = valid_wallets
    elif 0 <= wallet_idx < len(valid_wallets):
        export_data = [valid_wallets[wallet_idx]]
    else:
        print(f"{c['R']}❌ Pilihan tidak valid!"); input(f"{c['y']}Tekan Enter untuk kembali..."); return
    
    backup_json = []
    for w in export_data:
        backup_json.append({
            "address": w.addr,
            "private_key": w.priv,
            "public_key": w.pub,
            "rpc": w.rpc,
            "exported_at": datetime.now().isoformat()
        })
    
    filename = f"wallet_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    print(f"\n{c['B']}{c['c']}═══ EXPORT WALLET KEYS ═════════════════════════════════════════════════════════════════════")
    print(f"{c['R']}⚠️  WARNING: File ini berisi PRIVATE KEY! Simpan dengan aman!")
    print(f"{c['y']}📁 Filename: {filename}")
    print(f"{c['w']}Wallets: {len(backup_json)}")
    
    if input(f"{c['B']}{c['y']}Simpan ke file? (yes/no): {c['w']}").lower() == 'yes':
        try:
            with open(filename, 'w') as f:
                json.dump(backup_json, f, indent=2)
            print(f"{c['g']}✅ Backup berhasil disimpan ke: {filename}")
            print(f"{c['R']}⚠️  Jangan share file ini ke siapa pun!")
        except Exception as e:
            print(f"{c['R']}❌ Error: {e}")
    
    input(f"{c['y']}Tekan Enter untuk kembali ke menu utama...")

def clear_transaction_history():
    """Clear transaction log"""
    global transaction_log
    
    cls()
    display_header()
    
    print(f"{c['B']}{c['c']}═══ CLEAR TRANSACTION HISTORY ═════════════════════════════════════════════════════════════")
    print(f"{c['w']}Total transaksi: {len(transaction_log)}")
    
    if not transaction_log:
        print(f"{c['y']}📭 Tidak ada transaksi yang perlu dihapus")
        input(f"{c['y']}Tekan Enter untuk kembali..."); return
    
    if input(f"{c['R']}⚠️  Hapus SEMUA history? (yes/no): {c['w']}").lower() == 'yes':
        if input(f"{c['R']}Konfirmasi lagi (type 'DELETE'): {c['w']}").strip() == 'DELETE':
            transaction_log.clear()
            print(f"{c['g']}✅ History berhasil dihapus!")
        else:
            print(f"{c['y']}Dibatalkan")
    else:
        print(f"{c['y']}Dibatalkan")
    
    input(f"{c['y']}Tekan Enter untuk kembali ke menu utama...")

def display_wallet_explorer_detail():
    """Display detailed wallet explorer with fee estimation"""
    cls()
    display_header()
    display_wallet_table()
    
    print(f"\n{c['B']}{c['c']}═══ TRANSACTION LOG DETAIL ═══════════════════════════════════════════════════════════════════")
    
    if not transaction_log:
        print(f"{c['y']}📭 Tidak ada transaksi")
        input(f"{c['y']}Tekan Enter untuk kembali..."); return
    
    print(f"{c['w']}{'No':<4} {'Time':<8} {'Type':<7} {'Status':<8} {'Amount':<12} {'From':<20} {'To':<20} {'Hash':<15}")
    print(f"{c['c']}{'─'*4} {'─'*8} {'─'*7} {'─'*8} {'─'*12} {'─'*20} {'─'*20} {'─'*15}")
    
    for idx, log in enumerate(transaction_log[-50:], 1):
        status = "✅" if log['success'] else "❌"
        tx_type = log.get('type', 'Unknown')
        amount = log.get('amount', '0')
        from_addr = log.get('from_addr', '')[-15:] if log.get('from_addr') else 'N/A'
        to_addr = log.get('to_addr', '')[-15:] if log.get('to_addr') else 'N/A'
        tx_hash = log.get('hash', '')[:12] if log.get('hash') else 'N/A'
        
        print(f"{c['w']}{idx:<4} {log['time']:<8} {tx_type:<7} {status:<8} {amount:<12} {from_addr:<20} {to_addr:<20} {tx_hash:<15}")
    
    print(f"\n{c['y']}💡 Total transaksi tercatat: {len(transaction_log)}")
    input(f"{c['y']}Tekan Enter untuk kembali ke menu utama...")

async def main():
    """Main application function"""
    global session

    print(f"{c['B']}{c['g']}OCTra Multi-Wallet Advanced By Hokireceh")
    print(f"{c['w']}═════════════════════════════════════════════")
    print(f"{c['y']}New Features: Private Transactions, Encrypted Balance, Auto-Claim")
    print()

    # Load wallets
    if not load_wallets():
        return

    try:
        while True:
            cls()
            display_header()
            display_wallet_table()
            show_menu()

            choice = input(f"{c['B']}{c['y']}Pilih menu (0-C): {c['w']}").strip().upper()

            if choice == '1':
                await manual_send()
            elif choice == '2':
                await multi_send()
            elif choice == '3':
                await update_all_wallets()
                print(f"{c['g']}✅ Status wallet berhasil diperbarui!")
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '4':
                display_wallet_explorer_detail()
            elif choice == '5':
                cls()
                display_header()
                display_transaction_log()
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '6':
                await auto_claim_all_transfers()
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '7':
                await auto_encrypt_balances()
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '8':
                await auto_decrypt_balances()
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '9':
                export_wallet_keys()
            elif choice == 'A':
                clear_transaction_history()
            elif choice == 'B':
                cls()
                display_header()
                check_transaction_scanner()
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == 'C':
                if load_wallets():
                    print(f"{c['g']}✅ Wallet berhasil dimuat ulang!")
                else:
                    print(f"{c['R']}❌ Gagal memuat wallet!")
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")
            elif choice == '0':
                print(f"{c['y']}👋 Sampai jumpa!")
                break
            else:
                print(f"{c['R']}❌ Pilihan tidak valid!")
                input(f"{c['y']}Tekan Enter untuk melanjutkan...")

    except KeyboardInterrupt:
        print(f"\n{c['y']}🛑 Aplikasi dihentikan oleh pengguna")
    except Exception as e:
        print(f"\n{c['R']}💥 Error: {e}")
        logging.error(f"Main application error: {e}")
    finally:
        await close_session()

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully"""
    global session
    print(f"\n{c['y']}🛑 Menerima sinyal interrupt...")
    if session:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(close_session())
            else:
                loop.run_until_complete(close_session())
        except:
            pass
    sys.exit(0)

async def demo_mode():
    """Demo mode - automatically runs rotation for demonstration with private features"""
    print(f"{c['B']}{c['g']}🎮 MODE DEMO ADVANCED - ROTASI OTOMATIS")
    print(f"{c['w']}═══════════════════════════════════════════════════")
    print(f"{c['y']}Demo fitur: Public + Private transactions, Auto-claim, Encrypted balance")
    print(f"{c['y']}Tekan Ctrl+C untuk menghentikan kapan saja\n")

    # Load wallets
    if not load_wallets():
        return

    await update_all_wallets()

    try:
        demo_cycles = 0
        max_cycles = 15  # Extended demo cycles

        while demo_cycles < max_cycles:
            demo_cycles += 1
            cls()
            display_header()

            print(f"{c['B']}{c['c']}🎮 MODE DEMO ADVANCED - Siklus #{demo_cycles}/{max_cycles}")
            print()

            display_wallet_table()
            display_transaction_log()

            await auto_rotate_and_send_demo()

            # Wait before next cycle
            await asyncio.sleep(3)

        print(f"{c['g']}✅ Demo selesai! Total {demo_cycles} siklus dijalankan.")

    except KeyboardInterrupt:
        print(f"\n{c['y']}🛑 Demo dihentikan oleh pengguna")

async def auto_rotate_and_send_demo():
    """Demo version of rotation with private features"""
    global current_wallet_idx

    valid_wallets = [w for w in wallets if w.valid]
    if not valid_wallets:
        print(f"{c['R']}⚠️  Tidak ada wallet valid untuk demo!")
        await asyncio.sleep(2)
        return

    current_wallet = valid_wallets[current_wallet_idx % len(valid_wallets)]

    print(f"{c['B']}{c['c']}🔄 Demo: Memproses wallet {current_wallet_idx + 1}: {current_wallet.addr[:25]}...")

    # Simulate some processing
    await asyncio.sleep(1)

    # Generate target address from other wallets
    target_addresses = [w.addr for w in valid_wallets if w.addr != current_wallet.addr]

    if target_addresses:
        to_addr = random.choice(target_addresses)
        amount = 1.0

        # Randomly choose transaction type for demo
        tx_type = random.choice(['Public', 'Private', 'Private', 'Encrypt', 'Decrypt'])  # Bias towards private

        if tx_type == 'Encrypt':
            print(f"{c['y']}💰 Demo: Simulasi encrypt balance 5 OCT...")
            success = random.choice([True, True, False])  # 66% success rate
            result_hash = f"encrypt_demo_{random.randint(1000, 9999)}" if success else 'Encrypt Error'
            if success:
                current_wallet.balance = max(0, current_wallet.balance - 5)
                current_wallet.encrypted_balance += 5
                current_wallet.total_balance = current_wallet.balance + current_wallet.encrypted_balance
        elif tx_type == 'Decrypt':
            print(f"{c['y']}🔓 Demo: Simulasi decrypt balance 3 OCT...")
            success = random.choice([True, True, False])  # 66% success rate
            result_hash = f"decrypt_demo_{random.randint(1000, 9999)}" if success else 'Decrypt Error'
            if success and current_wallet.encrypted_balance >= 3:
                current_wallet.encrypted_balance = max(0, current_wallet.encrypted_balance - 3)
                current_wallet.balance += 3
                current_wallet.total_balance = current_wallet.balance + current_wallet.encrypted_balance
        else:
            print(f"{c['y']}🔒 Demo: Simulasi {tx_type.lower()} transaksi 1 OCT ke {to_addr[:25]}...")
            success = random.choice([True, True, False])  # 66% success rate
            result_hash = f"{tx_type.lower()}_demo_{random.randint(1000, 9999)}" if success else f'{tx_type} Error'

        # Add to transaction log
        log_entry = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'from_addr': current_wallet.addr,
            'to_addr': to_addr if tx_type != 'Encrypt' else 'Self',
            'amount': str(amount) if tx_type != 'Encrypt' else '5.0',
            'type': tx_type,
            'success': success,
            'hash': result_hash,
            'response': f'Demo {tx_type.lower()} transaction'
        }
        transaction_log.append(log_entry)

        if success:
            print(f"{c['g']}✅ Demo: {tx_type} simulasi berhasil!")
            current_wallet.nonce += 1
            if tx_type == 'Public' and current_wallet.balance > 0:
                current_wallet.balance = max(0, current_wallet.balance - amount)
            elif tx_type == 'Private' and current_wallet.encrypted_balance > 0:
                current_wallet.encrypted_balance = max(0, current_wallet.encrypted_balance - amount)

            if tx_type != 'Encrypt':
                current_wallet.total_balance = current_wallet.balance + current_wallet.encrypted_balance
        else:
            print(f"{c['R']}❌ Demo: Simulasi {tx_type.lower()} error/timeout")

    # Simulate auto-claim
    if random.choice([True, False]) and current_wallet.pending_private_transfers > 0:
        print(f"{c['g']}🎁 Demo: Auto-claiming private transfer...")
        claimed_amount = random.uniform(0.5, 2.0)
        current_wallet.encrypted_balance += claimed_amount
        current_wallet.total_balance += claimed_amount
        current_wallet.pending_private_transfers = max(0, current_wallet.pending_private_transfers - 1)
        await asyncio.sleep(1)

    # Move to next wallet
    current_wallet_idx = (current_wallet_idx + 1) % len(valid_wallets)

    # Short delay for demo
    delay = random.randint(3, 7)
    print(f"{c['y']}⏰ Demo: Menunggu {delay} detik sebelum wallet berikutnya...")
    await asyncio.sleep(delay)

if __name__ == "__main__":
    try:
        # Handle signals gracefully
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Check for demo mode
        if len(sys.argv) > 1 and sys.argv[1] == '--demo':
            asyncio.run(demo_mode())
        else:
            asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{c['y']}👋 Sampai jumpa!")
    except Exception as e:
        print(f"\n{c['R']}💥 Fatal error: {e}")
        logging.error(f"Fatal application error: {e}")
    finally:
        cls()
        print(f"{c['r']}")
        os._exit(0)
