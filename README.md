# Visual steganography using AES-algorithm

## Using Python
Python program that encrypts and decrypts the image files accurately. This will help in minimising the problem of data theft and leaks of other sensitive information. The file that we obtained after encryption is very safe and no cryptanalytic attacks. Data can be sent on a network without compromise of eavesdropping. At the receiver side, the receiver has code for decrypting the image so that data integrity is garunteed.

The demo video link is given below:\
https://youtu.be/4l-pS8uPaJ4

Recommended to used Linux based machine to avoid unexpected errors.\
System: Ubuntu18.04.2 on Oracle VM VirtualBox\
Python version: 2.7.17\
Libraries used:\
numpy 1.13.3\
Pillow 9.0.0\
pycryptodome 3.12.0 
OR Cryptodome\
PIL\
tkinter\
Tkinter [linux command: sudo apt-get install python-tk]

## Client-Server architecture using Javascript
Client requesting encryption of the image can upload the image, and this gets the client encrypted image downloaded in the defined folder, json formatted encypted image path, Initialization Value(IV) which needs is used by the server while decrypting. The server does the required function of encryption.

1. Run index.html\
Run using "Open with live server"\
This loads the frontend with upload functionality
2. Command to run backend via terminal: `node index.js`\
This loads the backend\
3. Upload the file, click UPLOAD
4. Get and copy the json formatted encypted image path, Initialization Value(IV)
5. For decryption, run the backend and start Postman.
6. Specify the URL as "http://localhost:3000/download"
7. Set the request as GET
8. Request is done through body, so set body as "raw" and format as "JSON"
9. In he body place the copied json message got after encryption
10. Click on SEND
11. You will get the decrypted image downloaded and shown as output

## Cryptography using Javascript Functions

**NOTE:** Image that is to be encrypted is already placed in the file. The file address is passed and image is read while encrypting\
Run `node using_fns.js` on terminal\
Get the encrypted and decrypted image
