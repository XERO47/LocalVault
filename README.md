```markdown
# 🔒 Secure Personal Vault – XERO47

A desktop application that turns any folder into an encrypted, password-protected vault for photos, documents, videos and private notes.  
Everything is stored with **AES-256-GCM**, **PBKDF2** (600 k iterations) and automatic memory scrubbing – no plaintext ever touches disk.

---

## Features

| Area | What you get |
|------|--------------|
| **Encryption** | AES-256-GCM, random 32-byte salt, 12-byte nonce, 16-byte auth-tag |
| **Key derivation** | PBKDF2-HMAC-SHA-256 @ 600 000 iterations |
| **Secure strings** | Password zeroed in RAM as soon as possible |
| **File vault** | Images, docs, videos, audio – drag & drop or browse |
| **Notebook** | Encrypted scratch-pad with auto-save |
| **Viewer** | Double-click → opens in default app; temp file auto-wiped after 5 min |
| **Delete** | 3-pass random overwrite + DB record purge |
| **Portability** | Single folder = vault (SQLite + meta). Move, backup, sync with Dropbox, etc. |
| **GUI** | Tkinter, dark theme, works on Windows / macOS / Linux |

---

## Quick start

1. Install dependencies  
   ```bash
   pip install cryptography pillow
   ```

2. Run  
   ```bash
   python main.py
   ```

3. Create a new vault (choose folder + master password ≥ 12 chars) or unlock an existing one.

---

## Vault anatomy

```
MyVault/
├── vault.db          # SQLite DB
│   ├── vault_meta    # salt + verification cipher
│   ├── files         # encrypted blobs
│   └── notebook      # encrypted text
└── (no other files – keep the folder private!)
```

---

## Security notes

* **Password**: never stored; only a verification tag encrypted with the derived key.  
* **Memory**: `SecureString` zeros itself on del; master-key reference cleared on lock/exit.  
* **Temp files**: exported items land in `tempfile.mkdtemp()` and are shredded after 5 min.  
* **Deletion**: file row removed + SQLite vacuum + 3-pass random overwrite of the db-wal.  
* **Side-channel**: no protection against cold-boot or RAM scraping – run on trusted machines.

---

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| Enter | Unlock vault (login screen) |
| Double-click | Open file (main screen) |
| Ctrl-S | Save notebook |

---

## Building a standalone binary (optional)

```bash
pip install pyinstaller
pyinstaller --onefile --add-data "*.png;." main.py
```

---

## License & disclaimer

This tool is for personal privacy only – not FIPS-140-2, not audited.  
Back-up your vault regularly; if you forget the password the data is unrecoverable.  
Use at your own risk.

---

## Author

XERO47 – pull requests welcome.
```
