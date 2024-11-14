from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import os
import base64

# Set the window size
WINDOW_WIDTH = 700
WINDOW_HEIGHT = 850

text1 = None
code = None
screen = None
private_key = None
public_key = None


# AES key generation and encryption/decryption
def generate_key(password):
    salt = b'secret_salt'  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(text_widget, password_var):
    password = password_var.get()
    if password:
        message = text_widget.get(1.0, END).strip()
        if message:
            key = generate_key(password)
            fernet = Fernet(key)
            encrypted_message = fernet.encrypt(message.encode())
            text_widget.delete(1.0, END)
            text_widget.insert(END, encrypted_message.decode())
            messagebox.showinfo("Success", "Text encrypted successfully!")
        else:
            messagebox.showwarning("Warning", "No message to encrypt")
    else:
        messagebox.showwarning("Warning", "Input Key")

def decrypt_message(text_widget, password_var):
    password = password_var.get()
    if password:
        message = text_widget.get(1.0, END).strip()
        if message:
            try:
                key = generate_key(password)
                fernet = Fernet(key)
                decrypted_message = fernet.decrypt(message.encode())
                text_widget.delete(1.0, END)
                text_widget.insert(END, decrypted_message.decode())
                messagebox.showinfo("Success", "Text decrypted successfully!")
            except Exception:
                messagebox.showerror("Error", "Invalid Key or Encrypted Message")
        else:
            messagebox.showwarning("Warning", "No message to decrypt")
    else:
        messagebox.showwarning("Warning", "Input Key")

# File and image encryption/decryption (AES)
def encrypt_file():
    password = code.get()
    if password:
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                file_data = file.read()
                key = generate_key(password)
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(file_data)

            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                       filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)
                messagebox.showinfo("Success", "File encrypted and saved successfully!")
    else:
        messagebox.showwarning("Warning", "Input Key")

def decrypt_file():
    password = code.get()
    if password:
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
                key = generate_key(password)
                fernet = Fernet(key)
                try:
                    decrypted_data = fernet.decrypt(encrypted_data)
                    save_path = filedialog.asksaveasfilename(defaultextension=".dec",
                                                               filetypes=[("Decrypted Files", "*.dec"), ("All Files", "*.*")])
                    if save_path:
                        with open(save_path, 'wb') as file:
                            file.write(decrypted_data)
                        messagebox.showinfo("Success", "File decrypted and saved successfully!")
                except Exception:
                    messagebox.showerror("Error", "Invalid Key or Encrypted File")
    else:
        messagebox.showwarning("Warning", "Input Key")

def encrypt_image():
    password = code.get()
    if password:
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'rb') as file:
                image_data = file.read()
                key = generate_key(password)
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(image_data)

            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                       filetypes=[("Encrypted Images", "*.enc"), ("All Files", "*.*")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)
                messagebox.showinfo("Success", "Image encrypted and saved successfully!")
    else:
        messagebox.showwarning("Warning", "Input Key")

def decrypt_image():
    password = code.get()
    if password:
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Images", "*.enc"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
                key = generate_key(password)
                fernet = Fernet(key)
                try:
                    decrypted_data = fernet.decrypt(encrypted_data)
                    save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                               filetypes=[("Images", "*.png"), ("All Files", "*.*")])
                    if save_path:
                        with open(save_path, 'wb') as file:
                            file.write(decrypted_data)
                        messagebox.showinfo("Success", "Image decrypted and saved successfully!")
                except Exception:
                    messagebox.showerror("Error", "Invalid Key or Encrypted Image")
    else:
        messagebox.showwarning("Warning", "Input Key")

# RSA Key Pair Generation and Message Signing/Verification
def generate_rsa_keypair():
    global private_key, public_key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    save_key = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
    if save_key:
        with open(save_key + "_private.pem", 'wb') as file:
            file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(save_key + "_public.pem", 'wb') as file:
            file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        messagebox.showinfo("Success", "RSA Key Pair generated and saved!")

from tkinter import filedialog
from cryptography.hazmat.primitives import serialization

# Function to sign the message with a private key
def sign_message():
    global private_key
    
    # Prompt user to load the private key for signing
    private_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
    if not private_key_path:
        messagebox.showwarning("Warning", "Private key file not selected!")
        return

    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load private key: {e}")
        return
    
    # Sign the message with the loaded private key
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showwarning("Warning", "No message to sign!")
        return
    
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Display the signed message and signature
    text1.delete(1.0, END)
    text1.insert(END, f"Message signed with signature:\n{base64.b64encode(signature).decode()}\n\n")
    
    # Save the signature to a file
    save_signature_path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])
    if save_signature_path:
        with open(save_signature_path, 'wb') as sig_file:
            sig_file.write(signature)
        messagebox.showinfo("Success", "Signature saved successfully!")
import base64
from tkinter import messagebox, filedialog

# Function to sign the message with the private key
def sign_message():
    global private_key
    
    # Load the private key for signing
    private_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
    if not private_key_path:
        messagebox.showwarning("Warning", "Private key file not selected!")
        return

    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # If the key is encrypted, you need to provide the password here
                backend=default_backend()
            )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load private key: {e}")
        return
    
    # Get the message from the input box
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showwarning("Warning", "No message to sign!")
        return
    
    # Sign the message
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save the signature to a file
    save_signature_path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])
    if save_signature_path:
        with open(save_signature_path, 'wb') as sig_file:
            sig_file.write(base64.b64encode(signature))  # Save as Base64 to make it portable
        messagebox.showinfo("Success", "Message signed and signature saved!")

# Function to verify the signature with a public key
def verify_signature():
    global public_key
    
    # Load the public key for verifying
    public_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
    if not public_key_path:
        messagebox.showwarning("Warning", "Public key file not selected!")
        return

    try:
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load public key: {e}")
        return
    
    # Prompt the user to load the signature file
    signature_path = filedialog.askopenfilename(filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])
    if not signature_path:
        messagebox.showwarning("Warning", "Signature file not selected!")
        return

    try:
        with open(signature_path, 'rb') as sig_file:
            signature = sig_file.read()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load signature: {e}")
        return

    # Decode the signature from Base64
    signature = base64.b64decode(signature)

    # Verify the message with the loaded public key and signature
    message = text1.get(1.0, END).strip()
    if not message:
        messagebox.showwarning("Warning", "No message to verify!")
        return

    try:
        public_key.verify(
            signature,
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        text1.insert(END, "\nSignature verification: SUCCESS")
    except Exception:
        text1.insert(END, "\nSignature verification: FAILED")

def reset_fields():
    text1.delete(1.0, END)
    code.set("")

def main_screen():
    global text1, code, screen
    screen = Tk()
    screen.geometry(f"{WINDOW_WIDTH+10}x{WINDOW_HEIGHT+10}")
    screen.title("...Cryptography Tool...")
    screen.configure(bg="#0c0c0c")

    # Moving text effect (subtle)
    def move_text():
        current_text = title.cget("text")
        new_text = current_text[1:] + current_text[0]
        title.config(text=new_text)
        screen.after(1000, move_text)

    # Blinking arrow (slow blink)
    def blink_symbol():
        current_symbol = arrow_label.cget("text")
        new_symbol = "" if current_symbol else ">>"
        arrow_label.config(text=new_symbol)
        screen.after(800, blink_symbol)

    # Gradient color effect for labels (slight)
    def change_color(label, color_list, index):
        label.config(fg=color_list[index])
        screen.after(150, lambda: change_color(label, color_list, (index + 1) % len(color_list)))

    rainbow_colors = ["#FF6347", "#FFA500", "#FFFF00", "#ADFF2F", "#00FFFF", "#1E90FF", "#9932CC"]

    # Moving text label
    title = Label(screen, text="Cryptography Tool ", bg="#0c0c0c", fg="#33ff33", font=("Courier New", 18))
    title.pack(pady=2)
    move_text()

    # Blinking arrow symbol
    arrow_label = Label(screen, text=">>", bg="#0c0c0c", fg="#33ff33", font=("Courier New", 16))
    arrow_label.pack(pady=5)
    blink_symbol()

    # Change colors of labels
    Label(screen, text="Enter text for encryption and decryption", bg="#0c0c0c", fg="#ffffff", font=("Courier New", 12)).pack(pady=10)
    text1 = Text(screen, font=("Courier New", 12), bg="#1c1c1c", fg="#33ff33", relief=GROOVE, wrap=WORD, bd=0, height=6)
    text1.pack(pady=5, padx=10)

    instruction_label = Label(screen, text="Enter secret key for encryption and decryption", bg="#0c0c0c", fg="#ffffff", font=("Courier New", 12))
    instruction_label.pack(pady=10)
    change_color(instruction_label, rainbow_colors, 0)

    code = StringVar()
    Entry(screen, textvariable=code, width=20, bd=2, font=("Courier New", 12), show="*").pack(pady=5)

    button_frame = Frame(screen, bg="#0c0c0c")
    button_frame.pack(pady=20)

    # Subtle hover effects for buttons
    def on_enter(e, btn):
        btn.config(bg="#00ff00")

    def on_leave(e, btn):
        btn.config(bg="#33ff33")

    def on_enter_decrypt(e, btn):
        btn.config(bg="#ff6347")

    def on_leave_decrypt(e, btn):
        btn.config(bg="#ed3833")

    encrypt_button = Button(button_frame, text="ENCRYPT TEXT", height=2, width=15, bg="#33ff33", fg="black", command=lambda: encrypt_message(text1, code))
    decrypt_button = Button(button_frame, text="DECRYPT TEXT", height=2, width=15, bg="#ed3833", fg="black", command=lambda: decrypt_message(text1, code))

    encrypt_button.grid(row=0, column=0, padx=10)
    decrypt_button.grid(row=0, column=1, padx=10)

    encrypt_button.bind("<Enter>", lambda e: on_enter(e, encrypt_button))
    encrypt_button.bind("<Leave>", lambda e: on_leave(e, encrypt_button))

    decrypt_button.bind("<Enter>", lambda e: on_enter_decrypt(e, decrypt_button))
    decrypt_button.bind("<Leave>", lambda e: on_leave_decrypt(e, decrypt_button))

    # Continue with other buttons
    encrypt_file_button = Button(button_frame, text="ENCRYPT FILE", height=2, width=15, bg="#33ff33", fg="black", command=encrypt_file)
    decrypt_file_button = Button(button_frame, text="DECRYPT FILE", height=2, width=15, bg="#ed3833", fg="black", command=decrypt_file)

    encrypt_file_button.grid(row=1, column=0, padx=10)
    decrypt_file_button.grid(row=1, column=1, padx=10)

    encrypt_image_button = Button(button_frame, text="ENCRYPT IMAGE", height=2, width=15, bg="#33ff33", fg="black", command=encrypt_image)
    decrypt_image_button = Button(button_frame, text="DECRYPT IMAGE", height=2, width=15, bg="#ed3833", fg="black", command=decrypt_image)

    encrypt_image_button.grid(row=2, column=0, padx=10)
    decrypt_image_button.grid(row=2, column=1, padx=10)

    Button(button_frame, text="RSA KEY PAIR", height=2, width=15, bg="#ffffff", command=generate_rsa_keypair).grid(row=3, columnspan=2, pady=10)
    Button(button_frame, text="SIGN MESSAGE", height=2, width=15, bg="#33ff33", command=sign_message).grid(row=4, column=0, pady=10)
    Button(button_frame, text="VERIFY SIGNATURE", height=2, width=15, bg="#33ff33", command=verify_signature).grid(row=4, column=1, pady=10)
    Button(button_frame, text="RESET", height=2, width=15, bg="#ffffff", command=reset_fields).grid(row=7, columnspan=2, pady=10)

    screen.mainloop()

main_screen()
