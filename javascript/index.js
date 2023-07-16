 const express = require('express');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
const upload = multer({ dest: 'uploads/' });
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key

const IV_LENGTH = 16;

app.use(express.static('uploads'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

app.post('/upload', upload.single('image'), (req, res) => {
  const uploadedFile = req.file;

  if (!uploadedFile) {
    return res.status(400).send('No file uploaded');
  }

  encryptImage(uploadedFile.path)
    .then(({ encryptedImagePath, iv }) => {
      res.send({ encryptedImagePath, iv: iv.toString('hex') });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send('Error encrypting image');
    });
});

app.get('/download', (req, res) => {
  const encryptedImagePath = req.body.encryptedImagePath;
  const iv = Buffer.from(req.body.iv, 'hex');

  if (!encryptedImagePath) {
    return res.status(400).send('No encrypted image path specified');
  }

  decryptImage(encryptedImagePath, iv)
    .then((decryptedImagePath) => {
      res.download(decryptedImagePath, 'decrypted_image.png', (error) => {
        if (error) {
          console.error(error);
          res.status(500).send('Error downloading decrypted image');
        } else {
          // Clean up decrypted image file
          fs.unlinkSync(decryptedImagePath);
        }
      });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send('Error decrypting image');
    });
});

function encryptImage(inputPath) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    const encryptedImagePath = `uploads/encrypted_${Date.now()}.png`;

    const writeStream = fs.createWriteStream(encryptedImagePath);
    const readStream = fs.createReadStream(inputPath);

    readStream.pipe(cipher).pipe(writeStream);

    writeStream.on('finish', () => {
      resolve({ encryptedImagePath, iv });
      console.log('Image encrypted successfully.');
    });

    writeStream.on('error', reject);
  });
}

function decryptImage(encryptedImagePath, iv) {
  return new Promise((resolve, reject) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    const decryptedImagePath = `uploads/decrypted_${Date.now()}.png`;

    const writeStream = fs.createWriteStream(decryptedImagePath);
    const readStream = fs.createReadStream(encryptedImagePath);

    readStream.pipe(decipher).pipe(writeStream);

    writeStream.on('finish', () => {
      resolve(decryptedImagePath);
      console.log('Image decrypted successfully.');
    });

    writeStream.on('error', reject);
  });
}

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
