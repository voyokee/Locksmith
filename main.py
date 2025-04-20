import sys
from PySide6.QtWidgets import (
    QApplication,  QMessageBox
)
from PySide6.QtCore import QFile
from config import *
from ui_masterpassword import MasterPasswordDialog
from ui_mainwindow import PasswordManagerWindow

  
# main
if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        first_time = not QFile(master_key_filename).exists()
        dialog = MasterPasswordDialog(first_time=first_time)
        dialog.show()
        app.exec()

        if dialog.accepted:
            window = PasswordManagerWindow()
            window.show()
            sys.exit(app.exec())
    except Exception as e:
        import traceback
        logging.error("Unhandled exception:\n" + traceback.format_exc())
        QMessageBox.critical(None, "Fatal Error", f"An unexpected error occurred:\n{e}")
        sys.exit(1)