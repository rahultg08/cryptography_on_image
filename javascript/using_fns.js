const fs = require('fs');
const aesjs = require('aes-js');
const crypto = require('crypto');

// Read the image file
const image = fs.readFileSync('Panda.png'); // Replace 'image.jpg' with the path to your image file

// Define the encryption function
function encryptImage(image, key) {
  const aesCtr = new aesjs.ModeOfOperation.ctr(key);
  const encryptedBytes = aesCtr.encrypt(image);
  return aesjs.utils.hex.fromBytes(encryptedBytes);
}

// Define the decryption function
function decryptImage(encryptedImage, key) {
  const aesCtr = new aesjs.ModeOfOperation.ctr(key);
  const encryptedBytes = aesjs.utils.hex.toBytes(encryptedImage);
  const decryptedBytes = aesCtr.decrypt(encryptedBytes);
  return Buffer.from(decryptedBytes);
}

// Generate a random encryption key
const key = crypto.randomBytes(32);

// Encrypt the image
const encryptedImage = encryptImage(image, key);

// Decrypt the image
const decryptedImage = decryptImage(encryptedImage, key);

// Write the decrypted image back to a file
fs.writeFileSync('decrypted_image.jpg', decryptedImage); // Replace 'decrypted_image.jpg' with the desired output file path
