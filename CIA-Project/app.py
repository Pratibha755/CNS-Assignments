from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64

# Set the window size
WINDOW_WIDTH = 400
WINDOW_HEIGHT = 650

text1 = None
code = None
screen = None

def main_screen():
    global text1, code, screen
    screen = Tk()
    screen.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
    screen.title("Secret Message Encryption Tool")
    screen.configure(bg="#0c0c0c")

    title = Label(text="Secret Message Encryption Tool", bg="#0c0c0c", fg="#33ff33", font=("Courier New", 20))
    title.pack(pady=10)

    Label(text="Enter text for encryption and decryption", bg="#0c0c0c", fg="#ffffff", font=("Courier New", 12)).pack(pady=10)
    text1 = Text(font=("Courier New", 12), bg="#1c1c1c", fg="#33ff33", relief=GROOVE, wrap=WORD, bd=0, height=6)
    text1.pack(pady=5, padx=10)

    Label(text="Enter secret key for encryption and decryption", bg="#0c0c0c", fg="#ffffff", font=("Courier New", 12)).pack(pady=10)
    code = StringVar()
    Entry(textvariable=code, width=20, bd=2, font=("Courier New", 12), show="*").pack(pady=5)

    # Create a frame for buttons
    button_frame = Frame(screen, bg="#0c0c0c")
    button_frame.pack(pady=20)

    # Create buttons
    Button(button_frame, text="ENCRYPT TEXT", height=2, width=15, bg="#33ff33", fg="black", command=lambda: encrypt_message(text1, code)).grid(row=0, column=0, padx=10)
    Button(button_frame, text="DECRYPT TEXT", height=2, width=15, bg="#ed3833", fg="black", command=lambda: decrypt_message(text1, code)).grid(row=0, column=1, padx=10)
    
    Button(button_frame, text="ENCRYPT FILE", height=2, width=15, bg="#33ff33", fg="black", command=encrypt_file).grid(row=1, column=0, padx=10)
    Button(button_frame, text="DECRYPT FILE", height=2, width=15, bg="#ed3833", fg="black", command=decrypt_file).grid(row=1, column=1, padx=10)
    
    Button(button_frame, text="ENCRYPT IMAGE", height=2, width=15, bg="#33ff33", fg="black", command=encrypt_image).grid(row=2, column=0, padx=10)
    Button(button_frame, text="DECRYPT IMAGE", height=2, width=15, bg="#ed3833", fg="black", command=decrypt_image).grid(row=2, column=1, padx=10)

    Button(button_frame, text="RESET", height=2, width=15, bg="#ffffff", command=reset).grid(row=3, columnspan=2, pady=10)

    screen.mainloop()

def generate_key(password):
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32)[:32])

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
        messagebox.showwarning("Warning", "Input Password")

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
        messagebox.showwarning("Warning", "Input Password")

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
        messagebox.showwarning("Warning", "Input Password")

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
        messagebox.showwarning("Warning", "Input Password")

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
        messagebox.showwarning("Warning", "Input Password")

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
                                                               filetypes=[("Images", "*.png;*.jpg"), ("All Files", "*.*")])
                    if save_path:
                        with open(save_path, 'wb') as file:
                            file.write(decrypted_data)
                        messagebox.showinfo("Success", "Image decrypted and saved successfully!")
                except Exception:
                    messagebox.showerror("Error", "Invalid Key or Encrypted Image")
    else:
        messagebox.showwarning("Warning", "Input Password")

def reset():
    global text1, code
    text1.delete(1.0, END)
    code.set("")
    messagebox.showinfo("Reset", "Fields reset successfully!")

main_screen()
