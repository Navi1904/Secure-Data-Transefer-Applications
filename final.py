import os
import time
import hashlib
from skimage.metrics import structural_similarity as compare_ssim
import cv2
from tkinter import Tk, Button, Entry, Label, filedialog, messagebox, Radiobutton, IntVar
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
from scipy.stats import entropy
import math
import tkinter as tk
 
# ----------------- Helper Functions ---------------------#
def image_to_bytes(image):
    pixels = np.array(image)
    return pixels.tobytes(), (image.width, image.height, pixels.shape[2])
 
def bytes_to_image(byte_data, dimensions):
    width, height, channels = dimensions
    pixels = np.frombuffer(byte_data, dtype=np.uint8).reshape((height, width, channels))
    return Image.fromarray(pixels)
 
def calculate_entropy(image):
    image_np = np.array(image)
    entropies = []
    for i in range(3):  
        channel = image_np[:, :, i]
        hist, _ = np.histogram(channel, bins=256, range=(0, 256), density=True)
        entropies.append(entropy(hist, base=2))
    return entropies
 
def calculate_psnr_mse(original, encrypted):
    original_np = np.array(original, dtype=np.float64) 
    encrypted_np = np.array(encrypted, dtype=np.float64)
 
    mse = np.sum((original_np - encrypted_np) ** 2) / (original_np.shape[0] * original_np.shape[1] * original_np.shape[2])
 
    psnr = 10 * np.log10(255 ** 2 / mse) if mse != 0 else float('inf')
 
    return psnr, mse
 
def calculate_ssim(original, encrypted):
    original_gray = cv2.cvtColor(np.array(original), cv2.COLOR_RGB2GRAY)
    encrypted_gray = cv2.cvtColor(np.array(encrypted), cv2.COLOR_RGB2GRAY)
    ssim, _ = compare_ssim(original_gray, encrypted_gray, full=True)
    return ssim
 
def hamming_encode(data):
    data_bits = [int(bit) for bit in data]
    encoded = []
    for i in range(0, len(data_bits), 4):
        nibble = data_bits[i:i + 4]
        if len(nibble) < 4:
            nibble += [0] * (4 - len(nibble))
        p1 = nibble[0] ^ nibble[1] ^ nibble[3]
        p2 = nibble[0] ^ nibble[2] ^ nibble[3]
        p3 = nibble[1] ^ nibble[2] ^ nibble[3]
        encoded += [p1, p2, nibble[0], p3, nibble[1], nibble[2], nibble[3]]
    return ''.join(map(str, encoded))
 
def hamming_decode(encoded):
    encoded_bits = [int(bit) for bit in encoded]
    decoded = []
    for i in range(0, len(encoded_bits), 7):
        group = encoded_bits[i:i + 7]
        p1 = group[0]
        p2 = group[1]
        d1 = group[2]
        p3 = group[3]
        d2 = group[4]
        d3 = group[5]
        d4 = group[6]
 
        c1 = p1 ^ d1 ^ d2 ^ d4
        c2 = p2 ^ d1 ^ d3 ^ d4
        c3 = p3 ^ d2 ^ d3 ^ d4
 
        error_pos = c1 * 1 + c2 * 2 + c3 * 4
        if error_pos != 0:
            group[error_pos - 1] ^= 1  
 
        decoded += [group[2], group[4], group[5], group[6]]
    return ''.join(map(str, decoded))
 
def string_to_binary(string):
    return ''.join(format(ord(char), '08b') for char in string)
 
def binary_to_string(binary):
    chars = [binary[i:i + 8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)
 
def validate_key_length(password, key_size):
    if key_size == 128 and len(password) < 4:
        messagebox.showerror("Input Error", "Please enter a secret key of at least 4 characters for 128-bit encryption.")
        return False
    elif key_size == 256 and len(password) < 8:
        messagebox.showerror("Input Error", "Please enter a secret key of at least 8 characters for 256-bit encryption.")
        return False
    return True
 # ----------------- Encryption Function ---------------------#
def encrypt_image(file_path, password, key_size):
    try:
        start_time = time.time()
 
        image = Image.open(file_path).convert("RGB")
        image_bytes, dimensions = image_to_bytes(image)
 
        red_entropy, green_entropy, blue_entropy = calculate_entropy(image)
        print(f"Original Image Entropy - R: {red_entropy:.4f}, G: {green_entropy:.4f}, B: {blue_entropy:.4f}")
 
        padded_bytes = pad(image_bytes, AES.block_size)
 
        if key_size == 128:
            key = hashlib.md5(password.encode()).digest()
        else:
            key = hashlib.sha256(password.encode()).digest()
        iv = os.urandom(16)
 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(padded_bytes)
 
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, "wb") as f:
            f.write(iv)
            f.write(f"{dimensions[0]},{dimensions[1]},{dimensions[2]}".encode().ljust(32, b'\x00'))
            f.write(encrypted_bytes)
 
        binary_password = string_to_binary(password)
        hamming_encoded_password = hamming_encode(binary_password)
        hamming_path = file_path + ".hamming"
        with open(hamming_path, "w") as f:
            f.write(hamming_encoded_password)
        print(f"Hamming encoded key saved to: {hamming_path}")
 
        visualization = np.frombuffer(encrypted_bytes[:dimensions[0] * dimensions[1] * 3], dtype=np.uint8)
        visualization = visualization.reshape((dimensions[1], dimensions[0], 3))
        visualized_image = Image.fromarray(visualization, mode="RGB")
        visualized_path = file_path.replace(".", "_encrypted_visual.")
        visualized_image.save(visualized_path)
 
        red_vis_entropy, green_vis_entropy, blue_vis_entropy = calculate_entropy(visualized_image)
        print(f"Encrypted Visualization Entropy - R: {red_vis_entropy:.4f}, G: {green_vis_entropy:.4f}, B: {blue_vis_entropy:.4f}")
 
        psnr, mse = calculate_psnr_mse(image, visualized_image)
        ssim = calculate_ssim(image, visualized_image)
        print(f"PSNR: {psnr:.2f} dB")
        print(f"MSE: {mse:.2f}")
        print(f"SSIM: {ssim:.4f}")
 
        end_time = time.time()
        print(f"Encryption Time: {end_time - start_time:.4f} seconds")
 
        messagebox.showinfo("Success", f"Encryption complete.\n"
                                       f"Metrics:\nPSNR: {psnr:.2f} dB\nMSE: {mse:.2f}\nSSIM: {ssim:.4f}")
 
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
def decrypt_image(file_path, password, key_size):
    try:
        start_time = time.time()
        
        root = tk.Tk()
        root.withdraw()  
        
        hamming_path = filedialog.askopenfilename(filetypes=[("Hamming Key Files", "*.hamming")])
        if hamming_path:
            with open(hamming_path, "r") as f:
                hamming_encoded_key = f.read()
 
            decoded_binary_key = hamming_decode(hamming_encoded_key)
            decoded_key = binary_to_string(decoded_binary_key)
 
            print(f"Decoded Secret Key (from .hamming file): {decoded_key}")
            
            messagebox.showinfo("Decoded Secret Key", f"The decoded secret key is: {decoded_key}")
 
            password_entry.delete(0, "end") 
            password_entry.config(state="normal")  
            def enable_key_entry():
                password_entry.config(state="normal")  
 
            root.after(2000, enable_key_entry) 
 
            def confirm_key():
                entered_key = password_entry.get()  
                if entered_key != decoded_key:
                    messagebox.showerror("Error", "The entered secret key does not match the decoded key. Please modify it and try again.")
                else:
                    proceed_with_decryption(file_path, entered_key, key_size, decoded_key, start_time)
 
            confirm_button = tk.Button(root, text="Confirm Key", command=confirm_key)
            confirm_button.pack(padx=10, pady=10)
 
            root.deiconify() 
        else:
            messagebox.showerror("Error", "Hamming encoded key not selected.")
            return
 
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
 
def proceed_with_decryption(file_path, entered_key, key_size, decoded_key, start_time):
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
 
        iv = file_content[:16]
        dimensions = tuple(map(int, file_content[16:48].strip(b'\x00').decode().split(',')))
        encrypted_bytes = file_content[48:]
 
        if key_size == 128:
            key = hashlib.md5(entered_key.encode()).digest()
        else:
            key = hashlib.sha256(entered_key.encode()).digest()
 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
 
        image = bytes_to_image(decrypted_bytes, dimensions)
        decrypted_path = file_path.replace(".enc", "_decrypted.png")
        image.save(decrypted_path)
 
        print(f"Decrypted image saved at: {decrypted_path}")
 
        original_file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if original_file_path:
            original_image = Image.open(original_file_path).convert("RGB")
 
            psnr, mse = calculate_psnr_mse(original_image, image)
            ssim = calculate_ssim(original_image, image)
 
            red_decrypted_entropy, green_decrypted_entropy, blue_decrypted_entropy = calculate_entropy(image)
 
            print(f"PSNR: {psnr:.2f} dB")
            print(f"MSE: {mse:.2f}")
            print(f"SSIM: {ssim:.4f}")
            print(f"Decrypted Image Entropy - R: {red_decrypted_entropy:.4f}, "
                  f"G: {green_decrypted_entropy:.4f}, B: {blue_decrypted_entropy:.4f}")
 
            messagebox.showinfo("Success", f"Decryption complete.\n"
                                           f"Metrics:\n"
                                           f"PSNR: {psnr:.2f} dB\n"
                                           f"MSE: {mse:.2f}\n"
                                           f"SSIM: {ssim:.4f}\n"
                                           f"Decrypted Image Entropy:\n"
                                           f"R: {red_decrypted_entropy:.4f}, "
                                           f"G: {green_decrypted_entropy:.4f}, "
                                           f"B: {blue_decrypted_entropy:.4f}")
 
        end_time = time.time()
        decryption_time = end_time - start_time
        print(f"Decryption Time: {decryption_time:.4f} seconds")
 
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        
                # ----------------- GUI Functions ---------------------#
def encrypt_action():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if file_path:
        password = password_entry.get()
        key_size = key_size_var.get()
        if validate_key_length(password, key_size):
            encrypt_image(file_path, password, key_size)
 
def decrypt_action():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = password_entry.get()
        key_size = key_size_var.get()
        if password:
            pass
        else:
            decrypt_image(file_path, password, key_size)
 
# ----------------- Main GUI ---------------------#
def main():
    global password_entry, key_size_var
 
    root = Tk()
    root.title("Image Encryption & Decryption")
    root.geometry("500x400")
    root.configure(bg="#2C3E50")
 
    Label(root, text="Enter Secret Key:", font=("Arial", 14), fg="#ECF0F1", bg="#2C3E50").pack(pady=10)
    password_entry = Entry(root, show="*", width=35, font=("Arial", 12), bg="#ECF0F1", fg="#2C3E50")
    password_entry.pack(pady=5)
 
    key_size_var = IntVar(value=128)  
    Label(root, text="Select Key Size:", font=("Arial", 14), fg="#ECF0F1", bg="#2C3E50").pack(pady=10)
 
    selected_key_label = Label(root, text="Current Key Size: 128-bit", font=("Arial", 12), fg="#ECF0F1", bg="#2C3E50")
    selected_key_label.pack(pady=5)
 
    def update_key_size_label():
        """Update the label to show the currently selected key size."""
        selected_key_label.config(text=f"Current Key Size: {key_size_var.get()}-bit")
 
    Radiobutton(
        root, text="128-bit", variable=key_size_var, value=128, font=("Arial", 12), 
        fg="#ECF0F1", bg="#34495E", selectcolor="#ECF0F1", command=update_key_size_label
    ).pack()
 
    Radiobutton(
        root, text="256-bit", variable=key_size_var, value=256, font=("Arial", 12), 
        fg="#ECF0F1", bg="#34495E", selectcolor="#ECF0F1", command=update_key_size_label
    ).pack()
 
    Button(root, text="Encrypt Image", command=encrypt_action, font=("Arial", 12), bg="#1ABC9C", fg="white", activebackground="#16A085", 
width=25).pack(pady=10)
    Button(root, text="Decrypt Image", command=decrypt_action, font=("Arial", 12), bg="#E74C3C", fg="white", activebackground="#C0392B", 
width=25).pack(pady=10)
 
    root.mainloop()
 
if __name__ == "__main__":
    main()
 