import string
import secrets
import zxcvbn

from cryptography.fernet import Fernet
from config import *

def generate_key():
    return Fernet.generate_key()


def load_key():
    with open(key_filename, "rb") as key_file:
        return key_file.read()

def save_key(key):
    with open(key_filename, "wb") as key_file:
        key_file.write(key)

def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())


def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()


def check_similarity(new_password, old_password):
    similarity = sum(1 for a, b in zip(new_password, old_password) if a == b)
    return similarity / max(len(new_password), len(old_password)) > 0.6


def generate_secure_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    character_pool = ''
    if use_upper:
        character_pool += string.ascii_uppercase
    if use_lower:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_symbols:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("Please select at least one character type.")

    return ''.join(secrets.choice(character_pool) for _ in range(length))


def check_password_strength_v1(password):
    # 长度限制
    if not (8 <= len(password) <= 16):
        return False, "Password length must be between 8 and 16 characters."

    # 检查是否为常见弱密码
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return False, "Password is too common or easily guessed."

    # 检查包含大写字母
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."

    # 检查包含小写字母
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."

    # 检查包含数字
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."

    # 检查包含特殊字符
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=~`[\]\\;/]', password):
        return False, "Password must contain at least one special character."

    return True, ""

def check_password_strength(password):
    # 使用zxcvbn进行密码强度检查
    result = zxcvbn.zxcvbn(password)
    score = result['score']

    # 基础检查
    if not (8 <= len(password) <= 16):
        return False, "Password length must be between 8 and 16 characters."

    # 检查是否为常见弱密码
    if password.lower() in COMMON_WEAK_PASSWORDS:
        return False, "Password is too common or easily guessed."

    # 根据zxcvbn的分数返回结果
    if score < 2:
        feedback = result['feedback']['warning'] if result['feedback']['warning'] else "Password is too weak."
        suggestions = result['feedback']['suggestions']
        if suggestions:
            feedback += "\nSuggestions:\n" + "\n".join(f"- {s}" for s in suggestions)
        return False, feedback

    return True, ""