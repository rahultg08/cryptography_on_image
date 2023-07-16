# ----------------- Header Files ---------------------#

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
from tkinter import *
from tkinter import filedialog, messagebox
import os
from PIL import Image, ImageTk
import math
# from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
import hashlib
import binascii
import numpy as np


# global password

def load_image(name):
    return Image.open(name)

# ----------------- Functions for encryption ---------------------#

def str_to_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode("utf-8")

def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(255)
            color2 = np.random.randint(255)
            color3 = np.random.randint(255)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x / 2), int(y / 2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return ciphered_image


def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x / 2), int(y / 2)), (color1, color2, color3))
    return new_image

def level_one_encrypt(Imagename):
    try:
        # reading in the image and size
        image = load_image(Imagename)
        size = image.size

        # Step 1: Preparing the secret image
        secret_image = generate_secret(size)

        # Step 2: Preparing the message image
        prepared_image = prepare_message_image(image, size)

        # Step 3: Generating the ciphered image
        ciphered_image = generate_ciphered_image(secret_image, prepared_image)

        # Saving the ciphered image
        ciphered_image.save("encrypted_image.png")
        messagebox.showinfo("Success", "Image encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def construct_enc_image(ciphertext, relength, width, height):
    while len(ciphertext) % relength != 0:
        ciphertext += " "

    # Convert to ASCII
    plain_image = []
    for i in range(0, len(ciphertext), relength):
        plain_image.append(ciphertext[i:i+relength])

    # Construct the encrypted image
    enc_image = Image.new('RGB', (width, height))
    pixel_index = 0
    for i in range(width):
        for j in range(height):
            rgb = []
            for k in range(3):
                rgb.append(int(binascii.hexlify(plain_image[pixel_index][k*2:k*2+2]), 16))
            enc_image.putpixel((i, j), tuple(rgb))
            pixel_index += 1
    return enc_image


def encrypt(imagename, password):
    try:
        # Opening the image
        image = load_image(imagename)
        width, height = image.size

        # Step 1: Converting pixel values to string
        pixel_values = list(image.getdata())
        str_pixel_values = ""
        for pixel in pixel_values:
            str_pixel_values += "".join([chr(int(val)) for val in pixel])

        # Step 2: Encrypting the string
        key = hashlib.sha256(str_to_bytes(password)).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Padding the input data
        block_size = 16
        padded_data = str_to_bytes(str_pixel_values)
        padding_length = block_size - (len(padded_data) % block_size)
        padded_data += bytes([padding_length]) * padding_length

        ciphertext = cipher.encrypt(padded_data)

        # Step 3: Constructing the encrypted image
        enc_image = construct_enc_image(ciphertext, len(str_pixel_values) // (width * height), width, height)

        # Saving the encrypted image
        enc_image.save("encrypted_image.png")
        messagebox.showinfo("Success", "Image encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt(ciphername, password):
    try:
        # Opening the encrypted image
        enc_image = load_image(ciphername)
        width, height = enc_image.size

        # Step 1: Reconstructing the list of RGB tuples from the encrypted image
        pixels = list(enc_image.getdata())
        relength = len(pixels[0]) // 3

        cipher_pixels = []
        for pixel in pixels:
            for val in pixel:
                cipher_pixels.append(format(val, '02x'))

        # Step 2: Decrypting the ciphered pixels
        key = hashlib.sha256(str_to_bytes(password)).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = binascii.unhexlify("".join(cipher_pixels))
        decrypted_text = cipher.decrypt(cipher_text)

        # Step 3: Removing the padding from the decrypted text
        padding_length = decrypted_text[-1]
        decrypted_text = decrypted_text[:-padding_length]

        # Step 4: Constructing the decrypted image
        dec_image = construct_enc_image(decrypted_text.decode("utf-8"), relength, width, height)

        # Saving the decrypted image
        dec_image.save("decrypted_image.png")
        messagebox.showinfo("Success", "Image decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

        messagebox.showerror("Error", str(e))



# ----------------- Functions for UI ---------------------#

# def open_file():
#     global filename
#     filename = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
#     if filename:
#         image = Image.open(filename)
#         image.thumbnail((300, 300))
#         img_label.configure(image=image)
#         img_label.image = image

def open_file():
    global filename, image_object, img_label_image
    filename = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if filename:
        image_object = Image.open(filename)
        image_object.thumbnail((300, 300))
        img_label_image = ImageTk.PhotoImage(image_object)
        img_label.configure(image=img_label_image)



def encrypt_image():
    if password_entry.get() == "":
        messagebox.showwarning("Warning", "Please enter a password!")
    elif not filename:
        messagebox.showwarning("Warning", "Please select an image!")
    else:
        encrypt(filename, password_entry.get())
        password_entry.delete(0, END)

def decrypt_image():
    if password_entry.get() == "":
        messagebox.showwarning("Warning", "Please enter the password!")
    elif not filename:
        messagebox.showwarning("Warning", "Please select an image!")
    else:
        decrypt(filename, password_entry.get())
        password_entry.delete(0, END)

# ----------------- Main Program ---------------------#

if __name__ == "__main__":
    # Creating the main window
    root = Tk()
    root.title("Image Encryption")

    # Creating the top frame
    top_frame = Frame(root)
    top_frame.pack(pady=10)

    # Creating the image label
    img_label = Label(top_frame, image=None)
    img_label.pack()

    # Creating the bottom frame
    bottom_frame = Frame(root)
    bottom_frame.pack(pady=10)

    # Creating the file open button
    open_button = Button(bottom_frame, text="Open Image", command=open_file)
    open_button.grid(row=0, column=0, padx=10)

    # Creating the password label
    password_label = Label(bottom_frame, text="Password:")
    password_label.grid(row=0, column=1)

    # Creating the password entry
    password_entry = Entry(bottom_frame, show="*")
    password_entry.grid(row=0, column=2, padx=10)

    # Creating the encrypt button
    encrypt_button = Button(bottom_frame, text="Encrypt Image", command=encrypt_image)
    encrypt_button.grid(row=1, column=0, pady=10)

    # Creating the decrypt button
    decrypt_button = Button(bottom_frame, text="Decrypt Image", command=decrypt_image)
    decrypt_button.grid(row=1, column=1, pady=10)

    # Running the main loop
    root.mainloop()
