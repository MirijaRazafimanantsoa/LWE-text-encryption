import sys
import json
import os
import ast
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLineEdit, QMessageBox, QLabel, QInputDialog, QHBoxLayout
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve, QRect
from lwe import LWE

class LWEEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.lwe = LWE(chunk_size=1000)
        self.initUI()
        self.app_dir = os.path.dirname(os.path.abspath(__file__))

    def initUI(self):
        self.setWindowTitle('LWE Encryptor')
        self.setGeometry(100, 100, 500, 250)
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QPushButton {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #4d4d4d;
            }
            QLineEdit {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
                border-radius: 5px;
            }
            QLabel {
                font-size: 14px;
                color: #ffffff;
            }
        """)
        layout = QVBoxLayout()

        self.label = QLabel('Encrypt/Decrypt Text Files or Images using LWE.')
        layout.addWidget(self.label)

        passphrase_layout = QHBoxLayout()
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_input.setPlaceholderText('Enter passphrase ({} characters)'.format(self.lwe.n * self.lwe.l))
        passphrase_layout.addWidget(self.passphrase_input)

        self.see_passphrase_button = QPushButton('Show')
        self.see_passphrase_button.setCheckable(True)
        self.see_passphrase_button.clicked.connect(self.toggle_passphrase_visibility)
        passphrase_layout.addWidget(self.see_passphrase_button)
        layout.addLayout(passphrase_layout)

        self.encrypt_action_button = QPushButton('Encrypt Text File')
        self.encrypt_action_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_action_button)

        self.decrypt_action_button = QPushButton('Decrypt Text File')
        self.decrypt_action_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_action_button)

        self.encrypt_image_button = QPushButton('Encode Image to Text')
        self.encrypt_image_button.clicked.connect(self.encode_image_to_text)
        layout.addWidget(self.encrypt_image_button)

        self.decrypt_image_button = QPushButton('Decode Text to Image')
        self.decrypt_image_button.clicked.connect(self.decode_text_to_image)
        layout.addWidget(self.decrypt_image_button)

        self.setLayout(layout)

        self.animation = QPropertyAnimation(self, b"geometry")
        self.animation.setDuration(500)
        self.animation.setStartValue(QRect(self.x(), self.y(), 0, 0))
        self.animation.setEndValue(self.geometry())
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.animation.start()

    def toggle_passphrase_visibility(self, checked):
        if checked:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.see_passphrase_button.setText('Hide')
        else:
            self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.see_passphrase_button.setText('Show')



    def encrypt_file(self):
        passphrase = self.passphrase_input.text()
        if len(passphrase) != self.lwe.n * self.lwe.l:
            QMessageBox.warning(self, 'Warning', 'Wrong passphrase length, check with someone who understands the code')
            return

        plaintext_path, _ = QFileDialog.getOpenFileName(self, "Select Text File to Encrypt", "", "Text Files (*.txt);;All Files (*)")
        if not plaintext_path:
            return

        crypted_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Text File", "", "Text Files (*.txt);;All Files (*)")
        if not crypted_path:
            return

        try:
            with open(plaintext_path, 'r') as f:
                message = f.read()

            self.lwe.secret_key = self.lwe.to_key(passphrase)
            self.lwe.generate_public_key()
            encrypted_message = self.lwe.send_encrypted_message(message)

            with open(crypted_path, 'w') as f:
                f.write(str(encrypted_message))
            QMessageBox.information(self, 'Success', f'File encrypted successfully to {crypted_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'An error occurred during encryption: {e}')

    def decrypt_file(self):
        passphrase, ok = self.get_passphrase()
        if not ok:
            return

        if len(passphrase) != self.lwe.n * self.lwe.l:
            QMessageBox.warning(self, 'Warning', f'Passphrase must be {self.lwe.n * self.lwe.l} characters long.')
            return

        crypted_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted Text File to Decrypt", "", "Text Files (*.txt);;All Files (*)")
        if not crypted_path:
            return

        decrypted_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted Text File", "", "Text Files (*.txt);;All Files (*)")
        if not decrypted_path:
            return

        try:
            with open(crypted_path, 'r') as f:
                encrypted_message_str = f.read()
                encrypted_message = ast.literal_eval(encrypted_message_str)

            self.lwe.secret_key = self.lwe.to_key(passphrase)
            decrypted_message = self.lwe.decrypt_message(encrypted_message)

            with open(decrypted_path, 'w') as f:
                f.write(decrypted_message)
            QMessageBox.information(self, 'Success', f'File decrypted successfully to {decrypted_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'An error occurred during decryption: {e}')

    

    def encode_image_to_text(self):
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image to Encode", "", "Image Files (*.png *.jpg *.jpeg *.bmp *.gif)")
        if not image_path:
            return

        output_file_path, _ = QFileDialog.getSaveFileName(self, "Save Encoded Image as Text", "", "Text Files (*.txt);;All Files (*)")
        if not output_file_path:
            return

        try:
            encoded_string = self.lwe.encode_image_to_string(image_path)
            with open(output_file_path, 'w') as f:
                f.write(encoded_string)
            QMessageBox.information(self, 'Success', f'Image encoded to text successfully to {output_file_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'An error occurred during image encoding: {e}')

    def decode_text_to_image(self):
        encoded_text_path, _ = QFileDialog.getOpenFileName(self, "Select Encoded Image Text File", "", "Text Files (*.txt);;All Files (*)")
        if not encoded_text_path:
            return

        output_image_path, _ = QFileDialog.getSaveFileName(self, "Save Decoded Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp *.gif)")
        if not output_image_path:
            return

        try:
            with open(encoded_text_path, 'r') as f:
                encoded_string = f.read()
            
            self.lwe.decode_string_to_image(encoded_string, output_image_path)
            QMessageBox.information(self, 'Success', f'Text decoded to image successfully to {output_image_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'An error occurred during image decoding: {e}')

    #def get_passphrase(self):
     #   passphrase, ok = QInputDialog.getText(self, 'Passphrase', f'Enter passphrase:', echo=QLineEdit.EchoMode.Password)
      #  return passphrase, ok
    

    def get_passphrase(self):
        dialog = QInputDialog(self)
        dialog.setWindowTitle("Passphrase")
        dialog.setLabelText("Enter passphrase:")
        dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        dialog.resize(400, 150)  # Make the dialog larger (width, height)

        ok = dialog.exec()

        passphrase = dialog.textValue()
        return passphrase, ok == QInputDialog.DialogCode.Accepted

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = LWEEncryptor()
    ex.show()
    sys.exit(app.exec())