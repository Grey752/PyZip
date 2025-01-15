import os
import zipfile
import shutil
import tempfile
import tkinter as tk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename, asksaveasfilename, askdirectory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import tkinterdnd2
import datetime
import atexit
import secrets
import json
import string
import webbrowser

def long_path(path):
    if os.name == 'nt' and not path.startswith('\\\\?\\'):
        path = os.path.abspath(path)
        return '\\\\?\\' + path
    return path

def normalize_path(path):
    if path.startswith('\\\\?\\'):
        return path[4:]
    return path

def get_file_info(path):
    stat = os.stat(path)
    size = stat.st_size
    mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
    
    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size/1024:.1f} KB" 
    else:
        size_str = f"{size/1024/1024:.1f} MB"
        
    time_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
    
    return size_str, time_str

def encrypt_file(file_path, password):
    """
    使用高强度加密算法加密文件
    """
    salt = secrets.token_bytes(32)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # 增加迭代次数
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    iv = secrets.token_bytes(16)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    with open(file_path, 'rb') as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    password_hash = base64.b64encode(password.encode()).decode()
    metadata = json.dumps({"password": password_hash}).encode()
    
    with open(file_path, 'wb') as f:
        metadata_len = len(metadata).to_bytes(4, byteorder='big')
        f.write(metadata_len + metadata + salt + iv + encrypted_data)

def decrypt_file(file_path, password=None):
    """
    解密文件
    """
    with open(file_path, 'rb') as f:
        metadata_len = int.from_bytes(f.read(4), byteorder='big')
        metadata = json.loads(f.read(metadata_len))
        if password:
            stored_password = base64.b64decode(metadata["password"]).decode()
            if password != stored_password:
                raise ValueError("密码错误")
        else:
            password = base64.b64decode(metadata["password"]).decode()
            
        salt = f.read(32)
        iv = f.read(16)
        encrypted_data = f.read()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

class PyZipEditor:
    def __init__(self):
        self.root = tkinterdnd2.Tk()
        self.root.title("PyZip编辑器")
        self.current_path = None
        self.temp_dir = None
        self.password = None
        
        # 注册退出时的清理函数
        atexit.register(self.cleanup)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 创建主界面
        self.create_gui()
        
    def cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
            self.temp_dir = None
            
    def on_closing(self):
        self.cleanup()
        self.root.destroy()
        
    def create_gui(self):
        new_btn = tk.Button(self.root, text="新建", command=self.create_pyzip)
        new_btn.pack(pady=10)
        
        open_btn = tk.Button(self.root, text="打开", command=self.open_pyzip) 
        open_btn.pack(pady=10)
        
        exit_btn = tk.Button(self.root, text="退出", command=self.root.quit)
        exit_btn.pack(pady=10)

        link = tk.Label(self.root, text="by:\nhttps://space.bilibili.com/3493120134088978?spm_id_from=333.337.0.0", fg="blue", cursor="hand2")
        link.pack(side=tk.BOTTOM, pady=10)
        link.bind("<Button-1>", lambda e: webbrowser.open("https://space.bilibili.com/3493120134088978?spm_id_from=333.337.0.0"))

    def create_pyzip(self):
        folder_path = askdirectory(title="选择要压缩的文件夹")
        if not folder_path:
            return
            
        file_path = asksaveasfilename(
            defaultextension=".pyzip",
            filetypes=[("PyZip files", "*.pyzip")]
        )
        if not file_path:
            return
            
        self.current_path = file_path
        chars = string.ascii_letters + string.digits + string.punctuation
        self.password = ''.join(secrets.choice(chars) for _ in range(32))
        
        try:
            temp_zip = tempfile.mktemp(suffix='.zip')
            
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zf.write(file_path, arcname)
            
            with open(temp_zip, 'rb') as f:
                zip_data = f.read()
                
            with open(self.current_path, 'wb') as f:
                f.write(zip_data)
                
            encrypt_file(self.current_path, self.password)
            
            os.remove(temp_zip)
            
            messagebox.showinfo("成功", "已创建新的PyZip文件")
        except Exception as e:
            messagebox.showerror("错误", "创建文件失败: " + str(e))
            self.current_path = None
            self.password = None

    def open_pyzip(self):
        file_path = askopenfilename(
            defaultextension=".pyzip",
            filetypes=[("PyZip files", "*.pyzip")]
        )
        if file_path:
            self.current_path = file_path
            try:
                self.temp_dir = tempfile.mkdtemp()
                temp_zip = os.path.join(self.temp_dir, "temp.zip")
                
                decrypted_data = decrypt_file(file_path)
                
                with open(temp_zip, 'wb') as f:
                    f.write(decrypted_data)
                
                os.startfile(long_path(temp_zip))
            except Exception as e:
                messagebox.showerror("错误", "无法打开文件: " + str(e))
                self.current_path = None
                self.password = None

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    editor = PyZipEditor()
    editor.run()
