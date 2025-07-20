from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import filedialog, messagebox

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Message Hider")
        self.root.geometry("400x350")

        # Operation choice
        tk.Label(root, text="Choose Operation:").pack(pady=5)
        self.operation = tk.StringVar(value="encrypt")
        tk.Radiobutton(root, text="Encrypt (Hide Message)", variable=self.operation, value="encrypt", command=self.toggle_message_entry).pack()
        tk.Radiobutton(root, text="Decrypt (Get Message)", variable=self.operation, value="decrypt", command=self.toggle_message_entry).pack()

        # GUI Elements
        tk.Label(root, text="Message:").pack(pady=5)
        self.message_entry = tk.Entry(root, width=40)
        self.message_entry.pack()

        tk.Label(root, text="Key (Password):").pack(pady=5)
        self.key_entry = tk.Entry(root, width=40, show="*")
        self.key_entry.pack()

        tk.Label(root, text="Image Path:").pack(pady=5)
        self.image_entry = tk.Entry(root, width=40)
        self.image_entry.pack()
        tk.Button(root, text="Browse Image", command=self.browse_image).pack(pady=5)

        tk.Button(root, text="Execute", command=self.execute).pack(pady=10)

    def toggle_message_entry(self):
        if self.operation.get() == "decrypt":
            self.message_entry.config(state="disabled")
            self.message_entry.delete(0, tk.END)  # Clear the field
        else:
            self.message_entry.config(state="normal")

    def browse_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg")])
        if file_path:
            self.image_entry.delete(0, tk.END)
            self.image_entry.insert(0, file_path)

    def aes_encrypt(self, message, key):
        key = key.ljust(16)[:16].encode('utf-8')
        cipher = AES.new(key, AES.MODE_ECB)
        padded_message = pad(message.encode('utf-8'), 16)
        encrypted = cipher.encrypt(padded_message)
        return base64.b64encode(encrypted).decode('utf-8')

    def aes_decrypt(self, encrypted_message, key):
        try:
            key = key.ljust(16)[:16].encode('utf-8')
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted = base64.b64decode(encrypted_message.encode('utf-8'))
            decrypted_padded = cipher.decrypt(encrypted)
            return unpad(decrypted_padded, 16).decode('utf-8')
        except:
            return "Decryption failed. Wrong key?"

    def encode_message(self, image_path, encrypted_message, output_path):
        img = Image.open(image_path).convert('RGB')
        pixels = np.array(img)
        binary_message = ''.join(format(ord(c), '08b') for c in encrypted_message) + '00000000'
        if len(binary_message) > pixels.size:
            messagebox.showerror("Error", "Message too big for image!")
            return False
        flat_pixels = pixels.flatten()
        for i in range(len(binary_message)):
            flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(binary_message[i])
        new_img = Image.fromarray(flat_pixels.reshape(pixels.shape).astype('uint8'), 'RGB')
        new_img.save(output_path)
        return True

    def decode_message(self, image_path):
        img = Image.open(image_path).convert('RGB')
        pixels = np.array(img).flatten()
        binary_message = ''
        for i in range(len(pixels)):
            bit = pixels[i] & 1
            binary_message += str(bit)
            if len(binary_message) >= 8 and binary_message[-8:] == '00000000':
                binary_message = binary_message[:-8]
                break
        message = ''
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            message += chr(int(byte, 2))
        return message

    def execute(self):
        operation = self.operation.get()
        key = self.key_entry.get()
        image_path = self.image_entry.get()

        if operation == "encrypt":
            message = self.message_entry.get()
            if not (message and key and image_path):
                messagebox.showerror("Error", "Please fill message, key, and image path!")
                return
            try:
                encrypted = self.aes_encrypt(message, key)
                if self.encode_message(image_path, encrypted, "stego_image.png"):
                    messagebox.showinfo("Success", "Message hidden in stego_image.png")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to hide message: {str(e)}")
        else:  # decrypt
            if not (key and image_path):
                messagebox.showerror("Error", "Please fill key and image path!")
                return
            try:
                encrypted = self.decode_message(image_path)
                decrypted = self.aes_decrypt(encrypted, key)
                messagebox.showinfo("Message", f"Decrypted message: {decrypted}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to retrieve message: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()