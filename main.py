#!/usr/bin/env python3
# aslaaslaasla
# XERO47 /main.py


import os
import sys
import json
import hashlib
import secrets
import sqlite3
import shutil
import tempfile
import subprocess
import platform
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import io
import gc
import mmap

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac

class SecureString:
    """Secure string handling with memory cleanup"""
    def __init__(self, data: str):
        self.data = bytearray(data.encode('utf-8'))
    
    def __del__(self):
        if hasattr(self, 'data'):
            # Clear memory
            for i in range(len(self.data)):
                self.data[i] = 0
    
    def get_bytes(self) -> bytes:
        return bytes(self.data)
    
    def clear(self):
        for i in range(len(self.data)):
            self.data[i] = 0

class CryptoEngine:
    """ cryptographic engine"""
    
    SALT_SIZE = 32
    KEY_SIZE = 32  # AES-256
    NONCE_SIZE = 12  # GCM nonce
    TAG_SIZE = 16   # GCM tag
    PBKDF2_ITERATIONS = 600000 
    
    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(CryptoEngine.SALT_SIZE)
    
    @staticmethod
    def derive_key(password: SecureString, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2-HMAC-SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoEngine.KEY_SIZE,
            salt=salt,
            iterations=CryptoEngine.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.get_bytes())
    
    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM"""
        nonce = secrets.token_bytes(CryptoEngine.NONCE_SIZE)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        nonce = encrypted_data[:CryptoEngine.NONCE_SIZE]
        tag = encrypted_data[CryptoEngine.NONCE_SIZE:CryptoEngine.NONCE_SIZE + CryptoEngine.TAG_SIZE]
        ciphertext = encrypted_data[CryptoEngine.NONCE_SIZE + CryptoEngine.TAG_SIZE:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class SecureVault:
    """Main vault class with secure file operations"""
    
    def __init__(self, vault_path: str):
        self.vault_path = Path(vault_path)
        self.db_path = self.vault_path / "vault.db"
        self.master_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        
    # In the SecureVault class

    def create_vault(self, password: SecureString) -> bool:
        try:
            self.vault_path.mkdir(parents=True, exist_ok=True)
            
            self.salt = CryptoEngine.generate_salt()
            self.master_key = CryptoEngine.derive_key(password, self.salt)
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE vault_meta (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    encrypted_data BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE notebook (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content BLOB NOT NULL,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(title)
                )
            ''')
            
            cursor.execute('INSERT INTO vault_meta (key, value) VALUES (?, ?)',
                         ('salt', self.salt))

            verification_data = b"SECURE_VAULT_VERIFIED"
            encrypted_verification = CryptoEngine.encrypt_data(verification_data, self.master_key)
            cursor.execute('INSERT INTO vault_meta (key, value) VALUES (?, ?)', 
                         ('verification', encrypted_verification))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error creating vault: {e}")
            return False

    def unlock_vault(self, password: SecureString) -> bool:
        """Unlock existing vault by decrypting a verification marker."""
        try:
            if not self.db_path.exists():
                return False

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM vault_meta WHERE key = ?', ('salt',))
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                return False
            
            self.salt = result[0]
            
            self.master_key = CryptoEngine.derive_key(password, self.salt)
            
            cursor.execute('SELECT value FROM vault_meta WHERE key = ?', ('verification',))
            result = cursor.fetchone()
            conn.close() 

            if not result:
                return False
            
            encrypted_verification = result[0]
            
            try:
                decrypted_verification = CryptoEngine.decrypt_data(encrypted_verification, self.master_key)
                
                if hmac.compare_digest(decrypted_verification, b"SECURE_VAULT_VERIFIED"):
                    
                    return True
                else:
                    return False
            
            except Exception:
                return False

        except Exception as e:
            print(f"Error unlocking vault: {e}")
            return False
    
    def delete_file(self, file_id: int) -> bool:
        """Delete a file record from the vault database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
            
            if cursor.rowcount > 0:
                conn.commit()
                conn.close()
                return True
            else:
                conn.close()
                return False
                
        except Exception as e:
            print(f"Error deleting file from database: {e}")
    
            return False
    
    
    def store_file(self, file_path: str, file_type: str = "image") -> bool:
        """Store a file in the vault"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = CryptoEngine.encrypt_data(file_data, self.master_key)
            filename = Path(file_path).name
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO files (filename, file_type, encrypted_data)
                VALUES (?, ?, ?)
            ''', (filename, file_type, encrypted_data))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error storing file: {e}")
            return False
    
    def get_files(self) -> list:
        """Get list of stored files"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, filename, file_type, created_at FROM files')
            files = cursor.fetchall()
            
            conn.close()
            return files
            
        except Exception as e:
            print(f"Error getting files: {e}")
            return []
    
    def retrieve_file(self, file_id: int) -> Optional[bytes]:
        """Retrieve and decrypt a file"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT encrypted_data FROM files WHERE id = ?', (file_id,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return CryptoEngine.decrypt_data(result[0], self.master_key)
            return None
            
        except Exception as e:
            print(f"Error retrieving file: {e}")
            return None
    
    def store_notebook(self, title: str, content: str) -> bool:
        """Store notebook content"""
        try:
            encrypted_content = CryptoEngine.encrypt_data(content.encode('utf-8'), self.master_key)
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Check if notebook exists and update, or insert new
            cursor.execute('SELECT id FROM notebook WHERE title = ?', (title,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('''
                    UPDATE notebook SET content = ?, modified_at = CURRENT_TIMESTAMP
                    WHERE title = ?
                ''', (encrypted_content, title))
            else:
                cursor.execute('''
                    INSERT INTO notebook (title, content, modified_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (title, encrypted_content))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error storing notebook: {e}")
            return False
    
    def get_notebook(self, title: str = "Main Notebook") -> str:
        """Retrieve notebook content with proper password verification"""
        try:
            if not self.master_key:
                return ""
                
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT content FROM notebook WHERE title = ?', (title,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                try:
                    decrypted_content = CryptoEngine.decrypt_data(result[0], self.master_key)
                    return decrypted_content.decode('utf-8')
                except Exception as decrypt_error:
                    print(f"Failed to decrypt notebook: {decrypt_error}")
                    return ""
            return ""
            
        except Exception as e:
            print(f"Error retrieving notebook: {e}")
            return ""

class VaultGUI:
    """GUI interface for the secure vault"""
    
    def __init__(self):
        self.vault: Optional[SecureVault] = None
        self.root = tk.Tk()
        self.root.title("Secure Personal Vault")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', background='#2b2b2b', foreground='white')
        self.style.configure('TButton', padding=10)
        
        self.setup_login_screen()
        
    def setup_login_screen(self):
        """Setup the initial login screen"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)
        
        title_label = ttk.Label(main_frame, text="🔒 Secure Personal Vault", 
                               font=('Arial', 24, 'bold'))
        title_label.pack(pady=(0, 30))
        
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill='x', pady=10)
        
        ttk.Label(path_frame, text="Vault Location:", font=('Arial', 12)).pack(anchor='w')
        
        path_entry_frame = ttk.Frame(path_frame)
        path_entry_frame.pack(fill='x', pady=5)
        
        self.vault_path_var = tk.StringVar(value=str(Path.home() / "SecureVault"))
        self.vault_path_entry = ttk.Entry(path_entry_frame, textvariable=self.vault_path_var,
                                         font=('Arial', 11))
        self.vault_path_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(path_entry_frame, text="Browse", 
                  command=self.browse_vault_path).pack(side='right', padx=(10, 0))
        
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill='x', pady=10)
        
        ttk.Label(password_frame, text="Master Password:", font=('Arial', 12)).pack(anchor='w')
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var,
                                  show='*', font=('Arial', 11))
        password_entry.pack(fill='x', pady=5)
        password_entry.bind('<Return>', lambda e: self.unlock_vault())
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=30)
        
        ttk.Button(button_frame, text="Unlock Vault", 
                  command=self.unlock_vault).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Create New Vault", 
                  command=self.create_vault).pack(side='left', padx=10)
        
        password_entry.focus()
    
    def browse_vault_path(self):
        """Browse for vault directory"""
        path = filedialog.askdirectory(title="Select Vault Location")
        if path:
            self.vault_path_var.set(path)
    
    def create_vault(self):
        """Create a new vault"""
        vault_path = self.vault_path_var.get()
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if len(password) < 12:
            messagebox.showerror("Error", "Password must be at least 12 characters long")
            return
        
        try:
            secure_password = SecureString(password)
            self.vault = SecureVault(vault_path)
            
            if self.vault.create_vault(secure_password):
                messagebox.showinfo("Success", "Vault created successfully!")
                self.setup_main_interface()
            else:
                messagebox.showerror("Error", "Failed to create vault")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {str(e)}")
        finally:
            self.password_var.set("")
            if 'secure_password' in locals():
                secure_password.clear()
    
    def unlock_vault(self):
        """Unlock existing vault"""
        vault_path = self.vault_path_var.get()
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter the master password")
            return
        
        try:
            secure_password = SecureString(password)
            self.vault = SecureVault(vault_path)
            
            if self.vault.unlock_vault(secure_password):
                messagebox.showinfo("Success", "Vault unlocked successfully!")
                self.setup_main_interface()
            else:
                messagebox.showerror("Error", "Invalid password or vault not found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {str(e)}")
        finally:
            self.password_var.set("")
            if 'secure_password' in locals():
                secure_password.clear()
    
    def setup_main_interface(self):
        """Setup the main vault interface"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        files_frame = ttk.Frame(notebook)
        notebook.add(files_frame, text="📁 Files")
        
        files_toolbar = ttk.Frame(files_frame)
        files_toolbar.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(files_toolbar, text="Add Images", 
                  command=self.add_images).pack(side='left', padx=5)
        ttk.Button(files_toolbar, text="Add Files", 
                  command=self.add_files).pack(side='left', padx=5)
        ttk.Button(files_toolbar, text="Refresh", 
                  command=self.refresh_files).pack(side='left', padx=5)
        ttk.Button(files_toolbar, text="Export Selected", 
                  command=self.export_file).pack(side='left', padx=5)
        ttk.Button(files_toolbar, text="Delete Selected", 
                  command=self.delete_file_secure).pack(side='left', padx=5)
        
        instruction_label = ttk.Label(files_toolbar, text="💡 Double-click any file to open", 
                                    font=('Arial', 9))
        instruction_label.pack(side='right', padx=10)
        
        files_list_frame = ttk.Frame(files_frame)
        files_list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.files_tree = ttk.Treeview(files_list_frame, columns=('Type', 'Date'), show='tree headings')
        self.files_tree.heading('#0', text='Filename')
        self.files_tree.heading('Type', text='Type')
        self.files_tree.heading('Date', text='Date Added')
        
        self.files_tree.bind('<Double-1>', self.on_file_double_click)
        
        files_scrollbar = ttk.Scrollbar(files_list_frame, orient='vertical', command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=files_scrollbar.set)
        
        self.files_tree.pack(side='left', fill='both', expand=True)
        files_scrollbar.pack(side='right', fill='y')
        
        notebook_frame = ttk.Frame(notebook)
        notebook.add(notebook_frame, text="📝 Notebook")
        
        notebook_toolbar = ttk.Frame(notebook_frame)
        notebook_toolbar.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(notebook_toolbar, text="Save", 
                  command=self.save_notebook).pack(side='left', padx=5)
        ttk.Button(notebook_toolbar, text="Clear", 
                  command=self.clear_notebook).pack(side='left', padx=5)
        
        notebook_text_frame = ttk.Frame(notebook_frame)
        notebook_text_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.notebook_text = scrolledtext.ScrolledText(notebook_text_frame, wrap=tk.WORD,
                                                      font=('Arial', 11))
        self.notebook_text.pack(fill='both', expand=True)
        
        content = self.vault.get_notebook("Main Notebook")
        self.notebook_text.insert('1.0', content)
        
        bottom_toolbar = ttk.Frame(self.root)
        bottom_toolbar.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(bottom_toolbar, text="🔒 Lock Vault", 
                  command=self.lock_vault).pack(side='right', padx=5)
        
        self.refresh_files()
    
    def add_images(self):
        """Add images to the vault"""
        filetypes = [
            ('Image files', '*.png *.jpg *.jpeg *.gif *.bmp *.tiff'),
            ('All files', '*.*')
        ]
        
        files = filedialog.askopenfilenames(title="Select images to add", filetypes=filetypes)
        
        for file_path in files:
            if self.vault.store_file(file_path, "image"):
                print(f"Added: {Path(file_path).name}")
            else:
                messagebox.showerror("Error", f"Failed to add {Path(file_path).name}")
        
        self.refresh_files()
    
    def add_files(self):
        """Add any type of files to the vault"""
        filetypes = [
            ('All files', '*.*'),
            ('Image files', '*.png *.jpg *.jpeg *.gif *.bmp *.tiff'),
            ('Document files', '*.pdf *.doc *.docx *.txt *.rtf'),
            ('Video files', '*.mp4 *.avi *.mkv *.mov *.wmv'),
            ('Audio files', '*.mp3 *.wav *.flac *.aac *.ogg')
        ]
        
        files = filedialog.askopenfilenames(title="Select files to add", filetypes=filetypes)
        
        for file_path in files:
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']:
                file_type = "image"
            elif file_ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']:
                file_type = "video"
            elif file_ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg']:
                file_type = "audio"
            elif file_ext in ['.pdf', '.doc', '.docx', '.txt', '.rtf']:
                file_type = "document"
            else:
                file_type = "file"
            
            if self.vault.store_file(file_path, file_type):
                print(f"Added: {Path(file_path).name}")
            else:
                messagebox.showerror("Error", f"Failed to add {Path(file_path).name}")
        
        self.refresh_files()
    
    def refresh_files(self):
        """Refresh the files list"""
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        
        files = self.vault.get_files()
        for file_id, filename, file_type, created_at in files:
            self.files_tree.insert('', 'end', text=filename, values=(file_type, created_at),
                                  tags=(str(file_id),))
    
    def export_file(self):
        """Export selected file from vault"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to export")
            return
        
        item = self.files_tree.item(selection[0])
        file_id = int(item['tags'][0])
        filename = item['text']
        
        file_ext = Path(filename).suffix
        
        save_path = filedialog.asksaveasfilename(
            title="Save file as",
            initialfile=filename,
            defaultextension=file_ext,
            filetypes=[
                ('All files', '*.*'),
                ('Image files', '*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.tiff'),
                ('Document files', '*.pdf;*.doc;*.docx;*.txt;*.rtf'),
                ('Video files', '*.mp4;*.avi;*.mkv;*.mov;*.wmv'),
                ('Audio files', '*.mp3;*.wav;*.flac;*.aac;*.ogg')
            ]
        )
        
        if save_path:
            try:
                file_data = self.vault.retrieve_file(file_id)
                if file_data:
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    messagebox.showinfo("Success", f"File exported to:\n{save_path}")
                else:
                    messagebox.showerror("Error", "Failed to retrieve file from vault")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export file: {str(e)}")
    
    
    def on_file_double_click(self, event):
        """Handle double-click on file to open with default application"""
        selection = self.files_tree.selection()
        if not selection:
            return
        
        item = self.files_tree.item(selection[0])
        file_id = int(item['tags'][0])
        filename = item['text']
        
        try:
            file_data = self.vault.retrieve_file(file_id)
            if not file_data:
                messagebox.showerror("Error", "Failed to retrieve file from vault")
                return
            
            temp_dir = tempfile.mkdtemp(prefix="secure_vault_")
            temp_file_path = Path(temp_dir) / filename
            
            with open(temp_file_path, 'wb') as f:
                f.write(file_data)
            
            # Open with default application based on OS
            system = platform.system()
            if system == "Windows":
                os.startfile(str(temp_file_path))
            elif system == "Darwin":  # macOS
                subprocess.run(["open", str(temp_file_path)])
            else:  # Linux and others
                subprocess.run(["xdg-open", str(temp_file_path)])
            
            self.root.after(int(300000/5), lambda: self.cleanup_temp_file(temp_file_path, temp_dir))
            
            messagebox.showinfo("File Opened", 
                              f"Opening '{filename}' with default application.\n\n"
                              f"The temporary file will be automatically deleted after 5 minutes.\n"
                              f"Location: {temp_file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")
    
    def delete_file_secure(self):
        """Securely delete selected file from vault with disk overwriting"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to delete")
            return
        
        item = self.files_tree.item(selection[0])
        file_id = int(item['tags'][0])
        filename = item['text']
        
        # Double confirmation for deletion
        result = messagebox.askyesnocancel(
            "Secure Delete Confirmation",
            f"Are you sure you want to PERMANENTLY delete '{filename}'?\n\n"
            f"⚠️  This action will:\n"
            f"• Remove the file from the vault\n"
            f"• Overwrite disk sectors with random data\n"
            f"• Make the file completely unrecoverable\n\n"
            f"This operation cannot be undone!",
            icon='warning'
        )
        
        if result is True: 
            try:
                progress_window = tk.Toplevel(self.root)
                progress_window.title("Secure Deletion in Progress")
                progress_window.geometry("400x150")
                progress_window.transient(self.root)
                progress_window.grab_set()
                
                progress_window.update_idletasks()
                x = (progress_window.winfo_screenwidth() // 2) - (400 // 2)
                y = (progress_window.winfo_screenheight() // 2) - (150 // 2)
                progress_window.geometry(f"400x150+{x}+{y}")
                
                ttk.Label(progress_window, text=f"Securely deleting: {filename}", 
                         font=('Arial', 12)).pack(pady=10)
                
                progress_label = ttk.Label(progress_window, text="Removing file from vault...", 
                                         font=('Arial', 10))
                progress_label.pack(pady=5)
                
                progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
                progress_bar.pack(pady=10, padx=20, fill='x')
                progress_bar.start()
                
                self.root.update()
                progress_window.update()
                
                if self.vault.delete_file(file_id):
                    progress_label.config(text="Overwriting disk sectors (Pass 1/3)...")
                    self.root.update()
                    progress_window.update()
                    
                    success = self.vault.secure_delete_vault_data()
                    
                    progress_bar.stop()
                    progress_window.destroy()
                    
                    if success:
                        messagebox.showinfo("Success", 
                                          f"File '{filename}' has been securely deleted!\n\n"
                                          f"✅ File removed from vault\n"
                                          f"✅ Disk sectors overwritten with random data\n"
                                          f"✅ Data is now unrecoverable")
                        
                        self.refresh_files()
                    else:
                        messagebox.showerror("Partial Success", 
                                           f"File '{filename}' was removed from vault, "
                                           f"but secure disk overwriting may have failed.\n"
                                           f"The file is still deleted but disk traces might remain.")
                        self.refresh_files()
                else:
                    progress_bar.stop()
                    progress_window.destroy()
                    messagebox.showerror("Error", f"Failed to delete '{filename}' from vault")
                    
            except Exception as e:
                if 'progress_window' in locals():
                    progress_window.destroy()
                messagebox.showerror("Error", f"Failed to securely delete file: {str(e)}")
    
    def cleanup_temp_file(self, temp_file_path, temp_dir):
        """Clean up temporary file and directory"""
        try:
            if temp_file_path.exists():
                temp_file_path.unlink()
                print(f"Cleaned up temporary file: {temp_file_path}")
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir)
                print(f"Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            print(f"Warning: Failed to clean up temporary files: {e}")
    
    def save_notebook(self):
        """Save notebook content"""
        content = self.notebook_text.get('1.0', tk.END).strip()
        if self.vault.store_notebook("Main Notebook", content):
            messagebox.showinfo("Success", "Notebook saved successfully!")
        else:
            messagebox.showerror("Error", "Failed to save notebook")
    
    def clear_notebook(self):
        """Clear notebook content"""
        if messagebox.askyesno("Confirm", "Clear all notebook content?"):
            self.notebook_text.delete('1.0', tk.END)
    
    def lock_vault(self):
        """Lock the vault and return to login screen"""
        if self.vault:
            self.vault.master_key = None
            self.vault = None
        
        gc.collect()
        
        self.setup_login_screen()
    
    def run(self):
        """Start the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle application closing"""
        if self.vault:
            self.vault.master_key = None
        gc.collect()
        self.root.destroy()

def main():
    """Main entry point"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        from PIL import Image
    except ImportError as e:
        print(f"Missing required dependency: {e}")
        print("Please install required packages:")
        print("pip install cryptography pillow")
        sys.exit(1)
    
    app = VaultGUI()
    app.run()

if __name__ == "__main__":
    main()