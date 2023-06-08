# ----------------- Header Files ---------------------#

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
from tkinter import *
from tkinter import filedialog, messagebox
import os
from PIL import Image
import math
# from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
import hashlib
import binascii
import numpy as np


global password

def load_image(name):
    return Image.open(name)

# ----------------- Functions for encryption ---------------------#
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
            str_pixel_values += "".join([chr(val) for val in pixel])

        # Step 2: Encrypting the string
        key = hashlib.sha256(password.encode("utf-8")).digest()
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(str_pixel_values.encode("utf-8"))

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
            rgb = ""
            for val in pixel:
                rgb += format(val, '02x')
            cipher_pixels.append(rgb)

        # Step 2: Converting the list of RGB tuples to string
        ciphertext = ""
        for pixel in cipher_pixels:
            for i in range(relength):
                ciphertext += chr(int(pixel[i*2:i*2+2], 16))

        # Step 3: Decrypting the string
        key = hashlib.sha256(password.encode("utf-8")).digest()
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext.encode("utf-8"))

        # Step 4: Constructing the decrypted image
        dec_image = Image.new('RGB', (width, height))
        pixel_index = 0
        for i in range(width):
            for j in range(height):
                rgb = []
                for k in range(3):
                    rgb.append(ord(plaintext[pixel_index + k]))
                dec_image.putpixel((i, j), tuple(rgb))
                pixel_index += 3

        # Saving the decrypted image
        dec_image.save("decrypted_image.png")
        messagebox.showinfo("Success", "Image decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ----------------- Main Program ---------------------#

if __name__ == '__main__':
    # Setup command line arguments
    parser = argparse.ArgumentParser(description="Image Steganography")

    parser.add_argument("-e", "--encrypt", help="Encrypt the image", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the image", action="store_true")
    parser.add_argument("-i", "--input", help="Input image path", type=str)
    parser.add_argument("-p", "--password", help="Encryption/Decryption password", type=str)

    args = parser.parse_args()

    # Check if input image and password are provided
    if not args.input or not args.password:
        parser.print_help()
        sys.exit(1)

    # Check if either encrypt or decrypt option is selected
    if not args.encrypt and not args.decrypt:
        parser.print_help()
        sys.exit(1)

    # Encrypt the image
    if args.encrypt:
        encrypt(args.input, args.password)

    # Decrypt the image
    if args.decrypt:
        decrypt(args.input, args.password)
