# DES
My implementation of DES (Data Encryption Standard) Algorithm

This repository aims to show my implementation of the DES algorithm, an example of a message encrypted using the algorithm, as well as an appropriate example of its drawbacks.

# message.txt: 
An example plaintext message that is to be encrypted using DES.

# encrypted.txt
The DES-encrypted version of the example plaintext message in message.txt in hex string format.

# DES.py
The Python code implementing the DES algorithm.

# image.ppm
This (along with image_enc.ppm) serves as an example of the drawbacks of DES. Encrypting this image in Electronic Code Book format with DES preserves the shape of the image even in encrypted form.

# image_enc.ppm
Encrypted version of image.ppm using DES. The shape of the image is preserved, which is not ideal for encrypting information.
