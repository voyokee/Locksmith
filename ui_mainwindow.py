from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QFrame, QFormLayout,
    QPushButton, QMessageBox, QListWidget, QProgressBar, QHBoxLayout, QSpinBox, QCheckBox,
    QTreeWidget, QTreeWidgetItem, QHeaderView
)
from db_utils import *
from crypto_utils import *
from config import *
from datetime import datetime, timedelta

class PasswordManagerWindow(QMainWindow):
    global pw_gen_length, pw_gen_use_upper, pw_gen_use_lower, pw_gen_use_digits, pw_gen_use_symbols
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setFixedSize(600, 720)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # 账户名
        self.project_name_label = QLabel("Accounts Name:")
        self.layout.addWidget(self.project_name_label)
        self.project_name_edit = QLineEdit()
        self.layout.addWidget(self.project_name_edit)

        # 网站
        self.website_label = QLabel("Website:")
        self.layout.addWidget(self.website_label)
        self.website_edit = QLineEdit()
        self.layout.addWidget(self.website_edit)

        # 密码
        self.password_label = QLabel("Password:")
        self.layout.addWidget(self.password_label)

        # 创建密码输入布局
        password_layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText(
            "8-16 characters, must include uppercase, lowercase, digit, and special character"
        )
        self.password_edit.textChanged.connect(self.check_password_strength)
        password_layout.addWidget(self.password_edit)

        # 添加显示/隐藏密码按钮
        self.toggle_password_button = QPushButton("👁")
        self.toggle_password_button.setFixedWidth(30)
        self.toggle_password_button.clicked.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.toggle_password_button)

        self.layout.addLayout(password_layout)

        # 添加密码强度指示器
        self.strength_label = QLabel("Password Strength:")
        self.layout.addWidget(self.strength_label)
        self.strength_bar = QProgressBar()
        self.strength_bar.setMinimum(0)
        self.strength_bar.setMaximum(4)
        self.layout.addWidget(self.strength_bar)
        self.strength_text = QLabel("")
        self.layout.addWidget(self.strength_text)

        # 保存按钮
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_password)
        self.layout.addWidget(self.save_button)

        # 账户列表按钮
        self.view_button = QPushButton("Accounts List")
        self.view_button.clicked.connect(self.view_passwords)
        self.layout.addWidget(self.view_button)

        # Delete password button
        self.delete_button = QPushButton("Delete Password")
        self.delete_button.clicked.connect(self.delete_password)
        self.layout.addWidget(self.delete_button)

        # 密码列表（初始化为None，避免冗余）
        self.passwords_list = None

        # 分隔线
        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.HLine)
        self.separator.setFrameShadow(QFrame.Sunken)
        self.separator.setLineWidth(4)
        self.layout.addWidget(self.separator)
        self.pw_gen_label = QLabel("Password Generator")
        self.layout.addWidget(self.pw_gen_label)

        # 密码生成选项
        self.generation_options_layout = QFormLayout()

        # 密码长度
        self.length_label = QLabel("Password Length (Range 4-32):")
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(4, 32)
        self.length_spinbox.setValue(pw_gen_length)
        self.length_spinbox.valueChanged.connect(self.update_length)
        self.generation_options_layout.addRow(self.length_label, self.length_spinbox)

        # 大写字母选项
        self.uppercase_check = QCheckBox("Include Uppercase Letters (A-Z)")
        self.uppercase_check.setChecked(pw_gen_use_upper)
        self.uppercase_check.toggled.connect(self.update_use_upper)
        self.generation_options_layout.addRow(self.uppercase_check)

        # 小写字母选项
        self.lowercase_check = QCheckBox("Include Lowercase Letters (a-z)")
        self.lowercase_check.setChecked(pw_gen_use_lower)
        self.lowercase_check.toggled.connect(self.update_use_lower)
        self.generation_options_layout.addRow(self.lowercase_check)

        # 数字选项
        self.digits_check = QCheckBox("Include Digits (0-9)")
        self.digits_check.setChecked(pw_gen_use_digits)
        self.digits_check.toggled.connect(self.update_use_digits)
        self.generation_options_layout.addRow(self.digits_check)

        # 特殊符号选项
        self.symbols_check = QCheckBox("Include Symbols (!@#$%^&*)")
        self.symbols_check.setChecked(pw_gen_use_symbols)
        self.symbols_check.toggled.connect(self.update_use_symbols)
        self.generation_options_layout.addRow(self.symbols_check)

        self.layout.addLayout(self.generation_options_layout)

        # 生成密码
        self.generated_password_label = QLabel("Generated Password:")
        self.layout.addWidget(self.generated_password_label)

        # 创建生成的密码输入布局
        generated_password_layout = QHBoxLayout()
        self.generated_password_edit = QLineEdit()
        self.generated_password_edit.setEchoMode(QLineEdit.Password)
        generated_password_layout.addWidget(self.generated_password_edit)

        # 添加显示/隐藏生成的密码按钮
        self.toggle_generated_password_button = QPushButton("👁")
        self.toggle_generated_password_button.setFixedWidth(30)
        self.toggle_generated_password_button.clicked.connect(self.toggle_generated_password_visibility)
        generated_password_layout.addWidget(self.toggle_generated_password_button)

        self.layout.addLayout(generated_password_layout)

        # 密码生成按钮
        self.generate_button = QPushButton("Generate Password")
        self.generate_button.clicked.connect(self.auto_generate_password)
        self.layout.addWidget(self.generate_button)

        self.key = None
        self.logger = logging.getLogger('password_manager')
        self.current_password_strength = None

        # 如不存在密码保存文件则创建一个
        if not os.path.exists(pw_filename):
            with open(pw_filename, "w") as file:
                file.write("")

        if USE_DATABASE_STORAGE and not os.path.exists(DB_NAME):
            create_database(DB_NAME)

    def toggle_password_visibility(self):
        if self.password_edit.echoMode() == QLineEdit.Password:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_password_button.setText("👁‍🗨")
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.toggle_password_button.setText("👁")

    def toggle_generated_password_visibility(self):
        if self.generated_password_edit.echoMode() == QLineEdit.Password:
            self.generated_password_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_generated_password_button.setText("👁‍🗨")
        else:
            self.generated_password_edit.setEchoMode(QLineEdit.Password)
            self.toggle_generated_password_button.setText("👁")

    def check_password_strength(self):
        password = self.password_edit.text()
        if not password:
            self.strength_bar.setValue(0)
            self.strength_text.setText("")
            self.current_password_strength = None
            return

        result = zxcvbn.zxcvbn(password)
        score = result['score']
        self.strength_bar.setValue(score)
        self.current_password_strength = result

        # 设置进度条颜色
        if score == 0:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: red; }")
            strength_text = "Very Weak"
        elif score == 1:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
            strength_text = "Weak"
        elif score == 2:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: yellow; }")
            strength_text = "Medium"
        elif score == 3:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: lightgreen; }")
            strength_text = "Strong"
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: green; }")
            strength_text = "Very Strong"

        self.strength_text.setText(f"Strength: {strength_text}")

    def save_password(self):
        self.load_key_and_create_fernet()
        project_name = self.project_name_edit.text()
        website = self.website_edit.text()
        password = self.password_edit.text()

        if not project_name or not password or not website:
            QMessageBox.warning(self, "Error", "Project name, website and password cannot be empty.")
            return

        # 密码强度检测
        is_strong, msg = check_password_strength(password)
        if not is_strong:
            reply = QMessageBox.warning(self, "Weak Password", msg + "\n\nDo you still want to save this password?",
                                      QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return

        old_password = self.get_encrypted_password_from_file(project_name, website)
        if USE_DATABASE_STORAGE:
            old_password = get_password_from_db(DB_NAME, project_name, website)
        else:
            old_password = self.get_encrypted_password_from_file(project_name, website)

        if old_password:
            old_decrypted = decrypt_password(old_password, self.key)
            if check_similarity(password, old_decrypted):
                QMessageBox.warning(self, "Similar Password", "New password is too similar to the old one.")
                return

        encrypted_password = encrypt_password(password, self.key).decode() if USE_DATABASE_STORAGE else encrypt_password(password, self.key)
        timestamp = datetime.now().isoformat()
        if USE_DATABASE_STORAGE:
          save_password_to_db(DB_NAME, project_name, website, encrypted_password, timestamp)
        else:
          self.save_password_to_file(project_name, website, encrypted_password)

        self.logger.info(f"Saved password for project: {project_name} ({website})")
        QMessageBox.information(self, "Success", "Password saved successfully.")
        self.project_name_edit.clear()
        self.website_edit.clear()
        self.password_edit.clear()

    def copy_password(self):
        self.load_key_and_create_fernet()
        selected_item = self.passwords_list.currentItem()
    
        # 兼容QTreeWidgetItem和QListWidgetItem
        if isinstance(self.passwords_list, QTreeWidget):
            if selected_item is None:
                QMessageBox.warning(self, "Error", "Please select a password entry.")
                return
            # 获取账户名和网站（树形结构：第0列和第1列）
            project_name = selected_item.text(0).strip()
            website = selected_item.text(1).strip()
            # 跳过分组节点（只有账户名，没有网站）
            if not website:
                QMessageBox.warning(self, "Error", "Please select a specific website entry.")
                return
        else:
            # 兼容旧的QListWidgetItem格式
            if selected_item is None:
                QMessageBox.warning(self, "Error", "Please select a password entry.")
                return
            text = selected_item.text()
            import re
            match = re.match(r"(.+?)\s*@\s*(.+?)(?:\s*\[EXPIRED\])?\s*\(Last Modified:", text)
            if match:
                project_name = match.group(1).strip()
                website = match.group(2).strip()
            else:
                QMessageBox.warning(self, "Error", "Invalid item format.")
                return
    
        # Get password from database or file based on configuration
        encrypted_password = None
        if USE_DATABASE_STORAGE:
            encrypted_password = get_password_from_db(DB_NAME, project_name, website)
            if encrypted_password is not None and isinstance(encrypted_password, str):
                encrypted_password = encrypted_password.encode()
        else:
            encrypted_password = self.get_encrypted_password_from_file(project_name, website)
    
        if encrypted_password:
            # Check if password is expired
            timestamp = None
            if USE_DATABASE_STORAGE:
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute('''SELECT timestamp FROM passwords
                        WHERE app_name = ? AND website = ?''',
                        (project_name, website))
                result = cursor.fetchone()
                conn.close()
                if result:
                    timestamp = result[0]
            else:
                with open(pw_filename, "r") as password_file:
                    for line in password_file:
                        parts = line.strip().split(":", 3)
                        if len(parts) >= 4 and parts[0] == project_name and parts[1] == website:
                            timestamp = parts[3]
    
            if timestamp:
                try:
                    timestamp_dt = datetime.fromisoformat(timestamp)
                    if datetime.now() - timestamp_dt > timedelta(days=PASSWORD_EXPIRY_DAYS):
                        reply = QMessageBox.warning(
                            self,
                            "Expired Password",
                            f"Password for {project_name} ({website}) is expired!\nDo you still want to copy it?",
                            QMessageBox.Yes | QMessageBox.No
                        )
                        if reply == QMessageBox.No:
                            return
                except ValueError:
                    self.logger.error(f"Invalid timestamp format when copying password for {project_name} @ {website}")
    
            decrypted_password = decrypt_password(encrypted_password, self.key)
            QApplication.clipboard().setText(decrypted_password)
            self.logger.info(f"Copied password for project: {project_name} ({website})")
            QMessageBox.information(self, "Copied", "Password copied to clipboard.")
        else:
            QMessageBox.warning(self, "Not Found", "Project name and website not found.")

    def get_encrypted_password_from_file(self, project_name, website):
        with open(pw_filename, "r") as password_file:
            for line in password_file:
                parts = line.strip().split(":", 3)
                if len(parts) >= 4 and parts[0] == project_name and parts[1] == website:
                    return parts[2].encode()
        return None

    def view_passwords(self):
        # 清空并设置树形控件
        if self.passwords_list is not None:
            self.layout.removeWidget(self.passwords_list)
            self.passwords_list.deleteLater()
        self.passwords_list = QTreeWidget()
        self.passwords_list.setHeaderLabels(["Account", "Website", "Last Modified", "Status"])
        self.passwords_list.setMinimumHeight(120)
        self.passwords_list.itemDoubleClicked.connect(self.copy_password)
        self.layout.insertWidget(self.layout.indexOf(self.view_button) + 1, self.passwords_list)

        # 获取所有密码记录（数据库或文件）
        records = []
        if USE_DATABASE_STORAGE:
            passwords = list_all_passwords_from_db(DB_NAME)
            for entry in passwords:
                project_name, website, _, timestamp = entry
                records.append((project_name, website, timestamp))
        else:
            with open(pw_filename, "r") as password_file:
                for line in password_file:
                    parts = line.strip().split(":", 3)
                    if len(parts) >= 4:
                        project_name, website, _, timestamp = parts
                        records.append((project_name, website, timestamp))

        # 先分组，再每组取最近5条
        from collections import defaultdict
        grouped = defaultdict(list)
        for project_name, website, timestamp in records:
            grouped[project_name].append((website, timestamp))
        # 按账户分组，每组只保留最近5条
        for project_name, items in grouped.items():
            items.sort(key=lambda x: x[1], reverse=True)
            grouped[project_name] = items[:5]

        # 展示
        for project_name, items in grouped.items():
            if len(items) == 1:
                website, timestamp = items[0]
                status = ""
                try:
                    dt = datetime.fromisoformat(timestamp)
                    if datetime.now() - dt > timedelta(days=PASSWORD_EXPIRY_DAYS):
                        status = "EXPIRED"
                    else:
                        status = "Available"
                except Exception:
                    status = "Available"
                QTreeWidgetItem(self.passwords_list, [project_name, website, timestamp, status])
            else:
                parent = QTreeWidgetItem(self.passwords_list, [project_name])
                for website, timestamp in items:
                    status = ""
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        if datetime.now() - dt > timedelta(days=PASSWORD_EXPIRY_DAYS):
                            status = "EXPIRED"
                        else:
                            status = "Available"
                    except Exception:
                        status = "Available"
                    QTreeWidgetItem(parent, ["", website, timestamp, status])

        self.passwords_list.expandAll()
        self.logger.info("Viewed passwords")

    def auto_generate_password(self):
        global pw_gen_length,pw_gen_use_upper,pw_gen_use_lower,pw_gen_use_digits,pw_gen_use_symbols
        generated = generate_secure_password(pw_gen_length,
                            pw_gen_use_upper,
                            pw_gen_use_lower,
                            pw_gen_use_digits,
                            pw_gen_use_symbols)
        self.generated_password_edit.setText(generated)

    def update_length(self, value):
        global pw_gen_length
        pw_gen_length = value

    def update_use_upper(self, checked):
        global pw_gen_use_upper
        pw_gen_use_upper = checked

    def update_use_lower(self, checked):
        global pw_gen_use_lower
        pw_gen_use_lower = checked

    def update_use_digits(self, checked):
        global pw_gen_use_digits
        pw_gen_use_digits = checked

    def update_use_symbols(self, checked):
        global pw_gen_use_symbols
        pw_gen_use_symbols = checked

    def load_key_and_create_fernet(self):
        try:
            self.key = load_key()
        except FileNotFoundError:
            self.key = generate_key()
            save_key(self.key)

    def delete_password(self):
        # 兼容QTreeWidgetItem和QListWidgetItem
        selected_item = self.passwords_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Error", "Please select a password to delete.")
            return
    
        if isinstance(self.passwords_list, QTreeWidget):
            project_name = selected_item.text(0).strip()
            website = selected_item.text(1).strip()
            if not website:
                QMessageBox.warning(self, "Error", "Please select a specific website entry.")
                return
        else:
            text = selected_item.text()
            import re
            match = re.match(r"(.+?)\s*@\s*(.+?)(?:\s*\[EXPIRED\])?\s*\(Last Modified:", text)
            if match:
                project_name = match.group(1).strip()
                website = match.group(2).strip()
            else:
                QMessageBox.warning(self, "Error", "Invalid item format.")
                return
    
        reply = QMessageBox.question(self, "Confirm Delete",
                               f"Are you sure you want to delete the password for {project_name} @ {website}?",
                               QMessageBox.Yes | QMessageBox.No)
    
        if reply == QMessageBox.Yes:
            if USE_DATABASE_STORAGE:
                delete_password_from_db(DB_NAME, project_name, website)
            else:
                # Remove from file
                lines = []
                with open(pw_filename, "r") as password_file:
                    lines = [
                        line for line in password_file
                        if not (line.startswith(f"{project_name}:{website}:"))
                    ]
                with open(pw_filename, "w") as password_file:
                    password_file.writelines(lines)
    
            self.logger.info(f"Deleted password for project: {project_name} ({website})")
            QMessageBox.information(self, "Success", "Password deleted successfully.")
            self.view_passwords()  # Refresh the list
    
    def save_password_to_file(self, project_name, website, password):
        # 使用ISO格式保存时间戳，确保格式统一
        timestamp = datetime.now().isoformat()
        lines = []
        # 读取所有非当前project_name和website的行
        if os.path.exists(pw_filename):
            with open(pw_filename, "r") as password_file:
                lines = [
                    line for line in password_file
                    if not (line.startswith(f"{project_name}:{website}:"))
                ]
        # 写回（覆盖）并追加新行
        with open(pw_filename, "w") as password_file:
            password_file.writelines(lines)
            # password 可能是bytes也可能是str
            if isinstance(password, bytes):
                password_str = password.decode()
            else:
                password_str = str(password)
            password_file.write(f"{project_name}:{website}:{password_str}:{timestamp}\n")
 