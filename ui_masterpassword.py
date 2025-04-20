import sys
import random
from PySide6.QtWidgets import QWidget, QVBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Qt
from crypto_utils import load_key, generate_key, save_key
from config import *
from cryptography.fernet import Fernet

class MasterPasswordDialog(QWidget):
    def __init__(self, first_time=False):
        super().__init__()
        self.setWindowTitle("Master Password")
        self.setFixedSize(400, 250)
        self.attempts = 0
        self.max_attempts = 3
        self.first_time = first_time

        # 主垂直布局
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # 标题
        self.label = QLabel("Set a Master Password:" if first_time else "Enter Master Password:")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(self.label)

        # 表单布局
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.setFormAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        form_layout.setHorizontalSpacing(10)
        form_layout.setVerticalSpacing(15)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setMinimumWidth(200)
        form_layout.addRow("Master Password:", self.password_edit)

        # 验证码相关控件，初始隐藏
        self.captcha_label = QLabel("（验证码将在多次失败后出现）")
        self.captcha_edit = QLineEdit()
        self.captcha_edit.setPlaceholderText("Enter CAPTCHA")
        self.captcha_label.setVisible(False)
        self.captcha_edit.setVisible(False)
        form_layout.addRow(self.captcha_label, self.captcha_edit)

        main_layout.addLayout(form_layout)

        # 提交按钮
        self.submit_button = QPushButton("Submit")
        self.submit_button.setFixedHeight(32)
        self.submit_button.setStyleSheet("font-size: 14px;")
        self.submit_button.clicked.connect(self.check_password)
        main_layout.addWidget(self.submit_button, alignment=Qt.AlignCenter)

        self.setLayout(main_layout)

        self.fernet = Fernet(self.load_or_generate_key())
        self.accepted = False

        self.captcha_answer = None
        self.show_captcha = False

    def load_or_generate_key(self):
        try:
            return load_key()
        except FileNotFoundError:
            key = generate_key()
            save_key(key)
            return key

    def generate_captcha(self):
        a = random.randint(1, 20)
        b = random.randint(1, 20)
        self.captcha_answer = str(a + b)
        self.captcha_label.setText(f"CAPTCHA: What is {a} + {b}?")
        self.captcha_edit.clear()
        self.captcha_label.setVisible(True)
        self.captcha_edit.setVisible(True)

    def check_password(self):
        global failed_logins, lockout_end_time
        password = self.password_edit.text()
        ip = '127.0.0.1'  # placeholder for real IP detection if networked

        if lockout_end_time and datetime.now() < lockout_end_time:
            QMessageBox.critical(self, "Locked", "Too many failed attempts. Try again later.")
            return

        # 输错1次后就显示验证码
        if not self.first_time and failed_logins.get(ip, 0) >= 1:
            self.show_captcha = True
            if not self.captcha_label.isVisible():
                self.generate_captcha()
            # 检查验证码
            if self.captcha_edit.text().strip() != self.captcha_answer:
                QMessageBox.warning(self, "CAPTCHA", "Incorrect CAPTCHA. Please try again.")
                self.generate_captcha()
                return
        else:
            self.captcha_label.setVisible(False)
            self.captcha_edit.setVisible(False)
            self.captcha_answer = None

        if self.first_time:
            encrypted = self.fernet.encrypt(password.encode())
            with open(master_key_filename, "wb") as f:
                f.write(encrypted)
            QMessageBox.information(self, "Success", "Master password set successfully!")
            self.accepted = True
            self.close()
        else:
            try:
                with open(master_key_filename, "rb") as f:
                    encrypted = f.read()
                decrypted = self.fernet.decrypt(encrypted).decode()
                if password == decrypted:
                    failed_logins[ip] = 0
                    self.accepted = True
                    self.close()
                else:
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1
                    logging.warning(f"Failed login attempt from IP {ip}. Count: {failed_logins[ip]}")
                    if failed_logins[ip] >= FAILED_LOGIN_LIMIT:
                        lockout_end_time = datetime.now() + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
                        QMessageBox.critical(self, "Locked", "Too many failed attempts. Try again later.")
                        return
                    # 输错1次后就显示验证码
                    if failed_logins[ip] >= 1:
                        self.show_captcha = True
                        self.generate_captcha()
                    QMessageBox.warning(self, "Incorrect",
                                        f"Wrong password. Attempts left: {FAILED_LOGIN_LIMIT - failed_logins[ip]}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                sys.exit()
