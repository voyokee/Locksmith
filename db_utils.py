import sqlite3
import logging

#存储密码至本地数据库
def create_database(db_name):
    """Creates a new SQLite database with password tables"""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create passwords table
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords(
                    app_name TEXT NOT NULL,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password BLOB NOT NULL,
                    timestamp TEXT NOT NULL,
                    PRIMARY KEY (app_name, website)
                    );''')

    conn.commit()
    conn.close()
    logging.info(f"Database {db_name} initialized")

def save_password_to_db(db_name, app_name, website, password, timestamp):
    """Save password to SQLite database"""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Check if entry exists and update or insert accordingly
    cursor.execute('''INSERT OR REPLACE INTO passwords
                   (app_name, website, username, password, timestamp)
                   VALUES (?, ?, ?, ?, ?)''',
                   (app_name, website, app_name, password, timestamp))

    conn.commit()
    conn.close()

def get_password_from_db(db_name, app_name, website):
    """Get password from SQLite database"""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''SELECT password FROM passwords
                   WHERE app_name = ? AND website = ?''',
                   (app_name, website))

    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    return None

def list_all_passwords_from_db(db_name):
    """Get all passwords from SQLite database"""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("SELECT app_name, website, password, timestamp FROM passwords")
    results = cursor.fetchall()

    conn.close()
    return results

def delete_password_from_db(db_name, app_name, website):
    """Delete password from SQLite database"""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''DELETE FROM passwords
                   WHERE app_name = ? AND website = ?''',
                   (app_name, website))

    conn.commit()
    conn.close()
 