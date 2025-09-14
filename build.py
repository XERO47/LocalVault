#!/usr/bin/env python3
"""
Build script to create a standalone executable from the Secure Vault application
This will bundle all dependencies and create a binary executable that doesn't require Python
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_dependencies():
    """Check if all required packages are installed"""
    required_packages = [
        'pyinstaller',
        'cryptography', 
        'pillow',
        'tkinter'  # Usually comes with Python
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'pillow':
                import PIL
            else:
                __import__(package)
            print(f"✅ {package} is installed")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} is missing")
    
    if missing_packages:
        print(f"\n📦 Installing missing packages...")
        for package in missing_packages:
            if package == 'tkinter':
                print("⚠️  tkinter usually comes with Python. If missing, install python-tk package")
                continue
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"✅ Installed {package}")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {package}")
                return False
    
    return True

def create_spec_file():
    """Create a custom PyInstaller spec file for advanced configuration"""
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.kdf',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.backends',
        'sqlite3',
        'secrets',
        'hmac',
        'hashlib',
        'tempfile',
        'subprocess',
        'platform',
        'shutil',
        'mmap',
        'gc'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy'],  # Exclude heavy packages
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # Compress executable
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='vault_icon.ico' if os.path.exists('vault_icon.ico') else None,
)
'''
    
    with open('secure_vault.spec', 'w') as f:
        f.write(spec_content.strip())
    
    print("✅ Created secure_vault.spec file")

def create_icon():
    """Create a simple icon for the executable"""
    try:
        from PIL import Image, ImageDraw
        
        # Create a 256x256 icon
        img = Image.new('RGBA', (256, 256), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw a vault-like icon
        # Outer circle (vault door)
        draw.ellipse([20, 20, 236, 236], fill='#2c3e50', outline='#34495e', width=8)
        
        # Inner circle
        draw.ellipse([60, 60, 196, 196], fill='#34495e', outline='#4a4a4a', width=4)
        
        # Lock mechanism
        draw.ellipse([100, 100, 156, 156], fill='#2c3e50', outline='#1a252f', width=3)
        draw.ellipse([118, 118, 138, 138], fill='#e74c3c', outline='#c0392b', width=2)
        
        # Handle
        draw.rectangle([140, 120, 200, 136], fill='#95a5a6', outline='#7f8c8d', width=2)
        draw.ellipse([190, 115, 205, 141], fill='#95a5a6', outline='#7f8c8d', width=2)
        
        # Save as ICO
        img.save('vault_icon.ico', format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
        print("✅ Created vault_icon.ico")
        return True
        
    except ImportError:
        print("⚠️  PIL not available for icon creation, continuing without icon")
        return False
    except Exception as e:
        print(f"⚠️  Failed to create icon: {e}")
        return False

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building executable...")
    
    try:
        # Run PyInstaller with the spec file
        cmd = [sys.executable, '-m', 'PyInstaller', '--clean', 'secure_vault.spec']
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Executable built successfully!")
            
            # Check if executable exists
            if sys.platform.startswith('win'):
                exe_path = Path('dist/SecureVault.exe')
            else:
                exe_path = Path('dist/SecureVault')
            
            if exe_path.exists():
                exe_size = exe_path.stat().st_size / (1024 * 1024)  # MB
                print(f"📁 Executable location: {exe_path.absolute()}")
                print(f"💾 Size: {exe_size:.1f} MB")
                return True
            else:
                print("❌ Executable not found after build")
                return False
        else:
            print("❌ Build failed!")
            print("Error output:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Build failed with error: {e}")
        return False

def cleanup():
    """Clean up build artifacts"""
    print("🧹 Cleaning up build artifacts...")
    
    cleanup_dirs = ['build', '__pycache__']
    cleanup_files = ['secure_vault.spec']
    
    for dir_name in cleanup_dirs:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
            print(f"🗑️  Removed {dir_name}")
    
    for file_name in cleanup_files:
        file_path = Path(file_name)
        if file_path.exists():
            file_path.unlink()
            print(f"🗑️  Removed {file_name}")

def main():
    """Main build process"""
    print("🚀 Secure Vault - Executable Builder")
    print("=" * 40)
    
    # Check if main script exists
    if not Path('main.py').exists():
        print("❌ main.py not found!")
        print("💡 Make sure the main vault script is named 'main.py' in the current directory")
        return False
    
    # Step 1: Check dependencies
    print("\n📦 Step 1: Checking dependencies...")
    if not check_dependencies():
        print("❌ Failed to install required packages")
        return False
    
    # Step 2: Create icon
    print("\n🎨 Step 2: Creating application icon...")
    create_icon()
    
    # Step 3: Create spec file
    print("\n⚙️  Step 3: Creating build configuration...")
    create_spec_file()
    
    # Step 4: Build executable
    print("\n🔨 Step 4: Building executable...")
    if not build_executable():
        return False
    
    # Step 5: Show results
    print("\n🎉 BUILD COMPLETED SUCCESSFULLY!")
    print("=" * 40)
    
    if sys.platform.startswith('win'):
        exe_name = 'SecureVault.exe'
    else:
        exe_name = 'SecureVault'
    
    print(f"✅ Executable created: dist/{exe_name}")
    print("📁 You can now distribute this single file")
    print("🔒 Your source code is protected and bundled")
    print("💻 No Python installation required on target machines")
    
    # Optional cleanup
    clean = input("\n🧹 Clean up build files? (y/N): ").lower().strip()
    if clean == 'y':
        cleanup()
    
    print("\n🎯 Usage Instructions:")
    print(f"1. Copy 'dist/{exe_name}' to any computer")
    print("2. Run the executable - no installation needed")
    print("3. Your vault files (.db and .salt) work with the executable")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        input("\nPress Enter to exit...")
        sys.exit(1)
    else:
        input("\nPress Enter to exit...")