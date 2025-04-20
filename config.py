import os
import logging

# 常见弱密码列表（已扩展，包含常见数字、键盘序列、简单单词等）
COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "abc123", "111111", "123123",
    "letmein", "welcome", "admin", "iloveyou", "1234", "000000", "password1", "12345", "1q2w3e4r",
    "sunshine", "princess", "football", "monkey", "charlie", "aa123456", "donald", "dragon", "qwertyuiop",
    "michael", "superman", "hottie", "loveme", "zaq12wsx", "password123", "qazwsx", "asdfgh", "asdfghjkl",
    "qwerty123", "qwe123", "passw0rd", "starwars", "654321", "987654321", "q1w2e3r4", "1qaz2wsx", "q1w2e3r4t5",
    "123qwe", "qweasd", "zxcvbnm", "zxcvbn", "test", "test123", "welcome1", "admin123", "letmein123"
}

PASSWORD_EXPIRY_DAYS = 30
FAILED_LOGIN_LIMIT = 5
LOCKOUT_DURATION_SECONDS = 60
failed_logins = {}
lockout_end_time = None
pw_gen_length=20
pw_gen_use_upper=True
pw_gen_use_lower=True
pw_gen_use_digits=True
pw_gen_use_symbols=True

# 获取当前文件所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 跨平台路径定义
pw_filename = os.path.join(BASE_DIR, "..", "passwords.txt")
key_filename = os.path.join(BASE_DIR, "..", "key.key")
master_key_filename = os.path.join(BASE_DIR, "..", "master.key")
DB_NAME = os.path.join(BASE_DIR, "password_vault.db")
LOG_FILENAME = os.path.join(BASE_DIR, "..", "password_manager.log")

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    filename=LOG_FILENAME,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)


USE_DATABASE_STORAGE = True  # Set to True to use SQLite, False to use file storage
lockout_end_time = None
failed_logins = {}