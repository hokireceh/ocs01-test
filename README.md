
# ocs01-test

Rust CLI untuk testing smart contract OCS01 dengan dukungan multi-wallet

## ✨ Fitur

- ✅ Testing semua method contract OCS01
- 🔄 Support multi-wallet (bisa pakai banyak wallet sekaligus)
- 📱 Interactive menu untuk navigasi mudah
- ⚡ Hasil instant untuk view methods
- 🔐 Handle tx signing untuk call methods
- 🔄 Switch wallet on-the-fly tanpa restart aplikasi

## 🖥️ Compatibility

- ✅ Linux
- ✅ macOS  
- ✅ Windows

## 📦 Install Rust (jika belum terinstall)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## 🔨 Build dari Source

```bash
git clone https://github.com/hokireceh/ocs01-test.git
cd ocs01-test
cargo build --release
```

## ⚙️ Setup

```bash
# copy contract interface
cp EI/exec_interface.json .
```

## 📁 File yang Diperlukan

File-file ini harus ada di directory yang sama:

### Multi-Wallet (Recommended)
- **`wallets.json`** - Konfigurasi multiple wallet
- **`exec_interface.json`** - Copy dari folder EI/

Format `wallets.json`:
```json
{
  "wallets": [
    {
      "name": "Wallet 1",
      "priv": "your_base64_private_key_here",
      "addr": "your_wallet_address_here", 
      "rpc": "https://octra.network"
    },
    {
      "name": "Wallet 2",
      "priv": "your_base64_private_key_here",
      "addr": "your_wallet_address_here",
      "rpc": "https://octra.network"
    }
  ]
}
```

### Single Wallet (Legacy Support)
- **`wallet.json`** - Single wallet config (untuk backward compatibility)
- **`exec_interface.json`** - Copy dari folder EI/

Format `wallet.json`:
```json
{
  "name": "My Wallet",
  "priv": "your_base64_private_key_here", 
  "addr": "your_wallet_address_here",
  "rpc": "https://octra.network"
}
```

## 🚀 Menjalankan

Binary release ada di folder ini setelah build berhasil:
```bash
./target/release/ocs01-test
```

*Untuk task ini, file EI berisi interface untuk contract di address `octBUHw585BrAMPMLQvGuWx4vqEsybYH9N7a3WNj1WBwrDn`, jangan dimodifikasi*

Setelah running, ikuti menu untuk berinteraksi dengan contract.

## 🎮 Cara Penggunaan

1. **Multi-Wallet Mode**: Jika ada file `wallets.json`, aplikasi akan menampilkan menu pemilihan wallet
2. **Switch Wallet**: Pilih option "switch wallet" untuk ganti wallet tanpa restart
3. **View Methods**: Hasil langsung tampil setelah eksekusi
4. **Call Methods**: Akan menghasilkan transaction hash dan bisa menunggu konfirmasi

## 🔧 Features Baru

- **Multi-Wallet Support**: Kelola multiple wallet dalam satu aplikasi
- **Runtime Wallet Switching**: Ganti wallet kapan saja tanpa restart
- **Enhanced UX**: Menu yang lebih user-friendly dengan nama wallet
- **Backward Compatibility**: Masih support format `wallet.json` lama

---

## 🙏 Support This Project

If you find this project helpful, you can support me via IDR USD or crypto ❤️

---
### ⚡ IDR (Rupiah)
- <b>[https://trakteer.id/garapanairdrop/tip](https://trakteer.id/garapanairdrop/tip)</b>

---

### ⚡ USD BNB ETH (EVM)
```bash
0x6ecc29eb11e73d12470bb80929d3a8f7b4e052ab
```

---

### ₿ Bitcoin (BTC)
```bash
bc1q9rgk0xg9ytrhrzyql4tduquk5tyl2k0ww7278l
```
