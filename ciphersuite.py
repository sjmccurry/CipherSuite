import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rsa
import os

def aes_encrypt(file_path, password):
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.aes', 'wb') as f:
        f.write(iv + ciphertext)

    messagebox.showinfo("Success", "File Encrypted successfully!")

def aes_decrypt(file_path, password):
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(file_path.replace('.aes', ''), 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", "File Decrypted successfully!")

def rsa_encrypt(file_path, password):
    (pubkey, privkey) = rsa.newkeys(512)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = rsa.encrypt(plaintext, pubkey)

    with open(file_path + '.rsa', 'wb') as f:
        f.write(ciphertext)

    with open(file_path + '.privkey', 'wb') as f:
        f.write(privkey.save_pkcs1())

    messagebox.showinfo("Success", "File Encrypted with RSA successfully!")

def rsa_decrypt(file_path, password):
    privkey_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("Private Key", "*.privkey")])
    
    if privkey_path:
        with open(privkey_path, 'rb') as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read())

        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        try:
            plaintext = rsa.decrypt(ciphertext, privkey)
            with open(file_path.replace('.rsa', ''), 'wb') as f:
                f.write(plaintext)
            messagebox.showinfo("Success", "File Decrypted successfully!")
        except rsa.DecryptionError:
            messagebox.showerror("Error", "Decryption failed! Incorrect key or corrupted file.")

def des_encrypt(file_path, password):
    key = password.encode('utf-8').ljust(8, b'\0')[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()
        padded_text = plaintext.ljust((len(plaintext) + 7) // 8 * 8, b'\0')

    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    with open(file_path + '.des', 'wb') as f:
        f.write(ciphertext)

    messagebox.showinfo("Success", "File Encrypted with DES successfully!")

def des_decrypt(file_path, password):
    key = password.encode('utf-8').ljust(8, b'\0')[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(file_path.replace('.des', ''), 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", "File Decrypted successfully!")

class EncryptionSuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSuite - Advanced Encryption")
        self.root.geometry('600x400')
        self.root.configure(bg='#f5f5f5')
        self.create_widgets()

    def create_widgets(self):
        self.menu_frame = tk.Frame(self.root, bg='#e0e0e0', padx=10)
        self.menu_frame.pack(side=tk.LEFT, fill=tk.Y)

        home_button = tk.Button(self.menu_frame, text="Home", command=self.show_home_page, bg='#d0d0d0', fg='#333', width=15, height=2, relief="flat")
        suite_button = tk.Button(self.menu_frame, text="Suite", command=self.show_suite_page, bg='#d0d0d0', fg='#333', width=15, height=2, relief="flat")
        home_button.pack(pady=5)
        suite_button.pack(pady=5)

        self.pages = tk.Frame(self.root, bg='#f5f5f5', padx=20, pady=20)
        self.pages.pack(fill=tk.BOTH, expand=True)

        self.home_frame = tk.Frame(self.pages, bg='#f5f5f5')
        home_label = tk.Label(self.home_frame, text="Welcome to CipherSuite", font=("Helvetica", 18, 'bold'), bg='#f5f5f5', fg='#333')
        instructions_label = tk.Label(self.home_frame, text="Use this suite to Encrypt or Decrypt Files", font=("Helvetica", 12), bg='#f5f5f5', fg='#666')
        github_link = tk.Label(self.home_frame, text="GitHub: https://github.com/sjmccurry", font=("Helvetica", 10, 'italic'), bg='#f5f5f5', fg='#007bff')
        home_label.pack(pady=20)
        instructions_label.pack(pady=10)
        github_link.pack(pady=10)

        self.suite_frame = tk.Frame(self.pages, bg='#f5f5f5')

        encryption_label = tk.Label(self.suite_frame, text="Encryption Suite", font=("Helvetica", 18, 'bold'), bg='#f5f5f5', fg='#333')
        encryption_label.pack(pady=10)

        self.encryption_type_var = tk.StringVar(self.suite_frame)
        encryption_type_label = tk.Label(self.suite_frame, text="Select Encryption Type:", bg='#f5f5f5', fg='#666')
        encryption_type_label.pack(pady=5)
        encryption_type_menu = tk.OptionMenu(self.suite_frame, self.encryption_type_var, "AES", "RSA", "DES")
        encryption_type_menu.config(bg='#d0d0d0', fg='#333', highlightbackground='#d0d0d0', width=20)
        encryption_type_menu.pack(pady=5)

        self.password_entry = tk.Entry(self.suite_frame, show="*", bg='#d0d0d0', fg='#333', borderwidth=1, relief="solid")
        password_label = tk.Label(self.suite_frame, text="Enter Password:", bg='#f5f5f5', fg='#666')
        password_label.pack(pady=5)
        self.password_entry.pack(pady=5, fill=tk.X)

        self.file_path = tk.StringVar(self.suite_frame)
        self.file_label = tk.Label(self.suite_frame, text="No file selected", bg='#f5f5f5', fg='#666')
        self.file_label.pack(pady=5)
        file_select_button = tk.Button(self.suite_frame, text="Select File", command=self.select_file, bg='#d0d0d0', fg='#333', width=20, relief="solid")
        file_select_button.pack(pady=5)

        button_frame = tk.Frame(self.suite_frame, bg='#f5f5f5')
        encrypt_button = tk.Button(button_frame, text="Encrypt", command=self.encrypt_file, bg="#a5d6a7", fg="#333", width=15, height=2, relief="solid")
        decrypt_button = tk.Button(button_frame, text="Decrypt", command=self.decrypt_file, bg="#ef9a9a", fg="#333", width=15, height=2, relief="solid")
        encrypt_button.pack(side=tk.LEFT, padx=10)
        decrypt_button.pack(side=tk.LEFT, padx=10)
        button_frame.pack(pady=20)

        self.show_home_page()

    def show_home_page(self):
        self.home_frame.pack(fill='both', expand=True)
        self.suite_frame.pack_forget()

    def show_suite_page(self):
        self.suite_frame.pack(fill='both', expand=True)
        self.home_frame.pack_forget()

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.file_label.config(text=os.path.basename(file_path))

    def encrypt_file(self):
        file_path = self.file_path.get()
        encryption_type = self.encryption_type_var.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        try:
            if encryption_type == "AES":
                aes_encrypt(file_path, password)
            elif encryption_type == "RSA":
                rsa_encrypt(file_path, password)
            elif encryption_type == "DES":
                des_encrypt(file_path, password)
            else:
                messagebox.showerror("Error", "Please select a valid encryption type.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed! {str(e)}")

    def decrypt_file(self):
        file_path = self.file_path.get()
        encryption_type = self.encryption_type_var.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        try:
            if encryption_type == "AES":
                aes_decrypt(file_path, password)
            elif encryption_type == "RSA":
                rsa_decrypt(file_path, password)
            elif encryption_type == "DES":
                des_decrypt(file_path, password)
            else:
                messagebox.showerror("Error", "Please select a valid encryption type.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed! {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionSuiteApp(root)
    root.mainloop()
