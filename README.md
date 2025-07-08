# LWE Encryptor

A simple file encryption utility using the [Learning with Errors](https://en.wikipedia.org/wiki/Learning_with_errors) (LWE) post-quantum cryptographic algorithm. This application provides a graphical user interface to encrypt/decrypt text files and encode/decode images.

## Features

-   **Text File Encryption:** Encrypt and decrypt text files using an LWE-based cryptosystem.
-   **Image Encoding:** Encode images into a base64 text format and decode them back to their original image format.
-   **Passphrase-Based Security:** Uses a user-provided passphrase to generate the secret key for encryption and decryption.
-   **User-Friendly GUI:** A simple and intuitive interface built with PyQt6.

## How It Works

The core of the application is a public-key cryptosystem based on the **Learning with Errors (LWE)** problem. The cryptographic logic is implemented in `lwe.py` and relies on the **SageMath** library for the necessary mathematical computations.

-   A secret key is generated from a user-provided passphrase. Its length should be a composite number (30 by default and can be modified throught the parameters `n` and `l` in `lwe.py`)
-   A corresponding public key is generated randomly from the secret key.
-   Messages are split into blocks and encrypted using the public key.
-   The GUI (`main.py`) provides an interface for users to select files, enter their passphrase, and perform the desired operations.

## Dependencies

To run this application, you will need:

-   **SageMath:** This project is built on the SageMath mathematical software system. You must run the script within a Sage environment.
-   **PyQt6:** The graphical user interface is built using the PyQt6 library.

## Installation

1.  **Install SageMath:**
    If you do not have SageMath installed, download and install it from the official website: [https://www.sagemath.org/download.html](https://www.sagemath.org/download.html)

2.  **Install PyQt6:**
    Open a terminal or command prompt and run the following command within the Sage environment to install PyQt6:
    ```bash
    sage -python -m pip install PyQt6
    ```
    If SageMath uses the system Python (for example, if installed via apt on Ubuntu), you can simply use:
    ```bash
    pip install pyqt6
    ```
    For Arch Based distros, you can use :
    ```bash
    sudo pacman -S python-pyqt6
    ```
## Usage

1.  Clone the repository :
```bash
git clone https://github.com/MirijaRazafimanantsoa/LWE-text-encryption.git
```
or download the `.zip` file
2.  Launch the application in a `Sagemath` environment:
```bash
sage main.py
```
### For text encryption
- Enter a passphrase of the required length to encrypt a text file (default is 30 characters, as `n*l = 6*5`).
- Select a text file to encrypt (for example `example_plaintext.txt`)
- Enter the name of the encrypted txt file (for example `encrypted.txt`)

### For image encryption
- Click on the `Encode Image to Text` button.
- Select an image (`example_image.jpg`) to encode.
- Choose a name for the encoded image (for example `encoded_image.txt`)
- Encrypt `encoded_image.txt` using the same steps as above.

### For text decryption
- Click on the `Decrypt text File` button.
- Enter the `same passphrase` used for the encryption of the file.
- Select the encrypted file (`encrypted.txt`)
- Choose a name for the retrieved file. You should be able to get the contents of `example_plaintext.txt` back.

### For image decryption
If you know that the encrypted file is an image,
- Decrypt the file using the same steps as text decryption (for example, choose `decrypted_image.txt` as the name)
- Click on the `Decode Text to Image` button.
- Select the wanted file (`decrypted_image.txt`)
- Choose a name for your image and you should see the initial image again.


## Additional remarks
- Encryption and decryption might take longer for larger image files.
- This project has not been tested on Windows yet. It may have issues or fail to run properly.

## Disclaimer

This is a personal project created for educational and demonstrative purposes. It has not been professionally audited for security.
