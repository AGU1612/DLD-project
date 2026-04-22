import sys
if sys.platform == "win32":
    import ctypes
    ctypes.windll.ole32.CoInitializeEx(None, 0x2)
import sys
import json
import csv
import os
import queue
import serial
import serial.tools.list_ports
from datetime import datetime
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QDialog, QListWidget, QListWidgetItem,
    QMessageBox, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QGridLayout, QDateEdit, QMenu, QSystemTrayIcon, QStyle,
    QLineEdit, QRadioButton, QButtonGroup, QSpinBox
)
from PyQt5.QtCore import Qt, QDate, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon
import threading
import hashlib
import base64
import secrets
from cryptography.fernet import Fernet

# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
SECRET_KEY   = "LCK9X3K7"
DB_FILE      = "lockers.json"
LOG_FILE     = "locker_log.csv"
LOCKER_COUNT = 7
BAUD_RATE    = 115200
PASSWORD_FILE = "locker_system.pwd"

# ─────────────────────────────────────────
# Password Manager
# ─────────────────────────────────────────
class PasswordManager:
    def __init__(self):
        self.password_file = PASSWORD_FILE
        self.salt = b"LockerSystemSalt2026"  # Fixed salt for deterministic key derivation
    
    def _derive_key(self, password):
        """Derive encryption key from password using hashlib."""
        # Use PBKDF2 via hashlib
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            self.salt,
            100000
        )
        # Ensure the key is 32 bytes for Fernet (base64 encoded to 44 bytes)
        key = base64.urlsafe_b64encode(dk)
        return key
    
    def set_password(self, password):
        """Encrypt and save password to file."""
        try:
            key = self._derive_key(password)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(password.encode())
            with open(self.password_file, 'wb') as f:
                f.write(encrypted)
            return True
        except Exception as e:
            print(f"Error setting password: {e}")
            return False
    
    def verify_password(self, password):
        """Verify that the provided password is correct."""
        try:
            if not os.path.exists(self.password_file):
                return False
            
            key = self._derive_key(password)
            cipher = Fernet(key)
            with open(self.password_file, 'rb') as f:
                encrypted = f.read()
            
            decrypted = cipher.decrypt(encrypted).decode()
            return decrypted == password
        except Exception:
            return False
    
    def password_exists(self):
        """Check if password file exists."""
        return os.path.exists(self.password_file)

# ─────────────────────────────────────────
# Password Dialogs
# ─────────────────────────────────────────
class SetPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Master Password")
        self.setMinimumWidth(350)
        self.setModal(True)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint)
        
        self.password = None
        
        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QLineEdit   {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px;
                padding: 8px; font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover { background: #45475a; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        title = QLabel("Set Master Password")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        desc = QLabel("Create a password to protect sensitive operations.\nThis will be required for locker access, admin panel, and backups.")
        desc.setStyleSheet("color: #a6e3a1; font-size: 11px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        layout.addSpacing(8)
        
        layout.addWidget(QLabel("Password:"))
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pwd_input)
        
        layout.addWidget(QLabel("Confirm Password:"))
        self.pwd_confirm = QLineEdit()
        self.pwd_confirm.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pwd_confirm)
        
        btn_row = QHBoxLayout()
        ok_btn = QPushButton("Set Password")
        ok_btn.setObjectName("success")
        ok_btn.clicked.connect(self._on_ok)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
    
    def _on_ok(self):
        pwd = self.pwd_input.text()
        confirm = self.pwd_confirm.text()
        
        if not pwd:
            QMessageBox.warning(self, "Empty Password", "Password cannot be empty.")
            return
        
        if pwd != confirm:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            self.pwd_input.clear()
            self.pwd_confirm.clear()
            return
        
        self.password = pwd
        self.accept()

class VerifyPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.setMinimumWidth(300)
        self.setModal(True)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint)
        
        self.password = None
        
        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QLineEdit   {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px;
                padding: 8px; font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover { background: #45475a; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        title = QLabel("Enter Master Password")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)
        
        layout.addWidget(QLabel("Password:"))
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.returnPressed.connect(self._on_ok)
        layout.addWidget(self.pwd_input)
        
        btn_row = QHBoxLayout()
        ok_btn = QPushButton("Verify")
        ok_btn.setObjectName("success")
        ok_btn.clicked.connect(self._on_ok)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
    
    def _on_ok(self):
        self.password = self.pwd_input.text()
        self.accept()
    
    def get_password(self):
        return self.password

class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Master Password")
        self.setMinimumWidth(350)
        self.setModal(True)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint)
        
        self.new_password = None
        
        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QLineEdit   {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px;
                padding: 8px; font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover { background: #45475a; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        title = QLabel("Change Master Password")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        layout.addWidget(QLabel("New Password:"))
        self.new_pwd_input = QLineEdit()
        self.new_pwd_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_pwd_input)
        
        layout.addWidget(QLabel("Confirm Password:"))
        self.new_pwd_confirm = QLineEdit()
        self.new_pwd_confirm.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_pwd_confirm)
        
        btn_row = QHBoxLayout()
        ok_btn = QPushButton("Change Password")
        ok_btn.setObjectName("success")
        ok_btn.clicked.connect(self._on_ok)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
    
    def _on_ok(self):
        pwd = self.new_pwd_input.text()
        confirm = self.new_pwd_confirm.text()
        
        if not pwd:
            QMessageBox.warning(self, "Empty Password", "Password cannot be empty.")
            return
        
        if pwd != confirm:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            self.new_pwd_input.clear()
            self.new_pwd_confirm.clear()
            return
        
        self.new_password = pwd
        self.accept()
    
    def get_new_password(self):
        return self.new_password

# ─────────────────────────────────────────
# Database
# ─────────────────────────────────────────
class Database:
    def __init__(self):
        self.data = self._load()

    def _load(self):
        print("Loading database...")
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "global_uids": [],
            "lockers": {
                str(i): {"uids": []} for i in range(1, LOCKER_COUNT + 1)
            }
        }

    def _save(self):
        try:
            with open(DB_FILE, "w") as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"DB save error: {e}")

    def _ensure_locker(self, locker_id):
        key = str(locker_id)
        if key not in self.data["lockers"]:
            self.data["lockers"][key] = {"uids": []}

    def get_locker_uids(self, locker_id):
        self._ensure_locker(locker_id)
        return list(self.data["lockers"][str(locker_id)]["uids"])

    def add_locker_uid(self, locker_id, uid):
        self._ensure_locker(locker_id)
        uids = self.data["lockers"][str(locker_id)]["uids"]
        if uid not in uids:
            uids.append(uid)
            self._save()

    def remove_locker_uid(self, locker_id, uid):
        self._ensure_locker(locker_id)
        uids = self.data["lockers"][str(locker_id)]["uids"]
        if uid in uids:
            uids.remove(uid)
            self._save()

    def reset_locker(self, locker_id):
        self._ensure_locker(locker_id)
        self.data["lockers"][str(locker_id)]["uids"] = []
        self.data["lockers"][str(locker_id)]["name"] = None
        self.data["lockers"][str(locker_id)]["roll_number"] = None
        self._save()

    def set_locker_allocation(self, locker_id, name, roll_number):
        self._ensure_locker(locker_id)
        self.data["lockers"][str(locker_id)]["name"] = name
        self.data["lockers"][str(locker_id)]["roll_number"] = roll_number
        self._save()

    def get_locker_allocation(self, locker_id):
        self._ensure_locker(locker_id)
        locker = self.data["lockers"][str(locker_id)]
        return {
            "name": locker.get("name"),
            "roll_number": locker.get("roll_number")
        }

    def get_global_uids(self):
        """Returns list of global UIDs (strings only)."""
        result = []
        global_uids = self.data.get("global_uids", [])
        for item in global_uids:
            if isinstance(item, dict):
                result.append(item.get("uid", ""))
            else:  # Old string format
                result.append(item)
        return result

    def add_global_uid(self, uid, name=None, roll_number=None):
        # Convert old string format to new object format if needed
        global_uids = self.data.get("global_uids", [])
        for item in global_uids:
            if isinstance(item, dict) and item.get("uid") == uid:
                return  # UID already exists
            elif item == uid:  # Old string format
                return
        
        self.data["global_uids"].append({
            "uid": uid,
            "name": name,
            "roll_number": roll_number
        })
        self._save()

    def remove_global_uid(self, uid):
        global_uids = self.data.get("global_uids", [])
        self.data["global_uids"] = [
            item for item in global_uids
            if not (isinstance(item, dict) and item.get("uid") == uid) and item != uid
        ]
        self._save()

    def reset_global_uids(self):
        self.data["global_uids"] = []
        self._save()
    
    def get_global_uids_with_details(self):
        """Returns global UIDs in consistent object format."""
        global_uids = self.data.get("global_uids", [])
        result = []
        for item in global_uids:
            if isinstance(item, dict):
                result.append(item)
            else:  # Old string format, convert to object
                result.append({"uid": item, "name": None, "roll_number": None})
        return result
    
    def update_global_uid_details(self, uid, name, roll_number):
        """Update name and roll number for an existing global UID."""
        global_uids = self.data.get("global_uids", [])
        for item in global_uids:
            if isinstance(item, dict) and item.get("uid") == uid:
                item["name"] = name
                item["roll_number"] = roll_number
                self._save()
                return

    def match_uid(self, locker_id, uid):
        if locker_id == 0:
            return False
        global_uids = self.data.get("global_uids", [])
        for item in global_uids:
            if isinstance(item, dict) and item.get("uid") == uid:
                return True
            elif item == uid:
                return True
        self._ensure_locker(locker_id)
        return uid in self.data["lockers"][str(locker_id)]["uids"]

# ─────────────────────────────────────────
# Logger
# ─────────────────────────────────────────
class Logger:
    def __init__(self):
        print("Loading logger...") 
        if not os.path.exists(LOG_FILE):
            self._write_header()

    def _write_header(self):
        try:
            with open(LOG_FILE, "w", newline="") as f:
                csv.writer(f).writerow(
                    ["timestamp", "locker_id", "uid", "status"]
                )
        except Exception as e:
            print(f"Log header error: {e}")

    def log(self, locker_id, uid, status):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", newline="") as f:
                csv.writer(f).writerow([timestamp, locker_id, uid, status])
        except Exception as e:
            print(f"Log write error: {e}")

    def read_all(self):
        try:
            if not os.path.exists(LOG_FILE):
                return []
            with open(LOG_FILE, "r") as f:
                return list(csv.DictReader(f))
        except Exception as e:
            print(f"Log read error: {e}")
            return []

    def clear(self):
        self._write_header()

    def clear_logs_by_time(self, mode, value, unit):
        """
        Clear logs based on time criteria.
        
        Args:
            mode (str): 'all', 'older_than', or 'last'
            value (int): Number of time units
            unit (str): 'hours', 'days', or 'months'
        """
        try:
            if mode == 'all':
                self._write_header()
                print(f"[LOG] Cleared ALL logs")
                return True
            
            from datetime import timedelta
            all_logs = self.read_all()
            
            if not all_logs:
                print("[LOG] No logs to process")
                return True
            
            # Convert unit to days for easier calculation
            if unit == 'hours':
                days_offset = value / 24.0
            elif unit == 'days':
                days_offset = value
            elif unit == 'months':
                days_offset = value * 30  # Approximate
            else:
                days_offset = value
            
            cutoff_time = datetime.now() - timedelta(days=days_offset)
            
            print(f"[LOG] Processing {len(all_logs)} total logs")
            print(f"[LOG] Mode: {mode}, Value: {value}, Unit: {unit}")
            print(f"[LOG] Cutoff time: {cutoff_time}")
            
            remaining_logs = []
            deleted_count = 0
            
            for log in all_logs:
                try:
                    log_time = datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S")
                    
                    if mode == 'older_than':
                        # DELETE logs OLDER than cutoff
                        # KEEP logs NEWER than or equal to cutoff
                        if log_time >= cutoff_time:
                            remaining_logs.append(log)
                            print(f"[LOG] KEEP: {log['timestamp']} (>= {cutoff_time})")
                        else:
                            deleted_count += 1
                            print(f"[LOG] DELETE: {log['timestamp']} (< {cutoff_time})")
                    
                    elif mode == 'last':
                        # DELETE logs from the LAST X period
                        # KEEP logs OLDER than cutoff
                        if log_time < cutoff_time:
                            remaining_logs.append(log)
                            print(f"[LOG] KEEP: {log['timestamp']} (< {cutoff_time})")
                        else:
                            deleted_count += 1
                            print(f"[LOG] DELETE: {log['timestamp']} (>= {cutoff_time})")
                
                except ValueError as e:
                    # If timestamp is malformed, keep the log
                    print(f"[LOG] KEEP (bad timestamp): {log.get('timestamp', 'unknown')}")
                    remaining_logs.append(log)
            
            print(f"[LOG] Total deleted: {deleted_count}, Remaining: {len(remaining_logs)}")
            
            # Write remaining logs back
            with open(LOG_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "locker_id", "uid", "status"])
                for log in remaining_logs:
                    writer.writerow([
                        log.get('timestamp', ''),
                        log.get('locker_id', ''),
                        log.get('uid', ''),
                        log.get('status', '')
                    ])
            return True
        except Exception as e:
            print(f"Error clearing logs by time: {e}")
            import traceback
            traceback.print_exc()
            return False

# ─────────────────────────────────────────
# Serial Worker
# ─────────────────────────────────────────
class SerialWorker:
    def __init__(self, port):
        self.port    = port
        self.ser     = None
        self.q       = queue.Queue()
        self.running = False
        self._thread = None
        self._send_lock = threading.Lock()

    def start(self):
        self.ser = serial.Serial(
            self.port,
            BAUD_RATE,
            timeout=0.1,     # short timeout so loop stays responsive
            write_timeout=0.1
        )
        self.running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="SerialReader"
        )
        self._thread.start()

    def _loop(self):
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.ole32.CoInitializeEx(None, 0x2)
        buf = b""
        while self.running:
            try:
                if not self.ser or not self.ser.is_open:
                    break
                chunk = self.ser.read(64)
                if chunk:
                    buf += chunk
                    while b"\n" in buf:
                        line_b, buf = buf.split(b"\n", 1)
                        line = line_b.decode("utf-8", errors="ignore").strip()
                        if line:
                            self.q.put(line)
            except serial.SerialException as e:
                self.q.put(f"SERIAL_ERROR:{e}")
                break
            except Exception as e:
                self.q.put(f"SERIAL_ERROR:{e}")
                break
        self.running = False

    def send(self, msg):
        with self._send_lock:
            try:
                if self.ser and self.ser.is_open:
                    self.ser.write((msg + "\n").encode("utf-8"))
            except Exception as e:
                print(f"Send error: {e}")

    def stop(self):
        self.running = False
        try:
            if self.ser and self.ser.is_open:
                self.ser.close()
        except Exception:
            pass

# ─────────────────────────────────────────
# Card Dialog (for admin cards with name/roll)
# ─────────────────────────────────────────
class CardDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Card")
        self.setMinimumWidth(350)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowCloseButtonHint
        )
        self.name = None
        self.roll_number = None

        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QLineEdit   {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px; padding: 8px;
                font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover   { background: #45475a; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Add Card")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)

        # Name input
        layout.addWidget(QLabel("User Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter user name")
        layout.addWidget(self.name_input)

        # Roll number input
        layout.addWidget(QLabel("Roll Number ID:"))
        self.roll_input = QLineEdit()
        self.roll_input.setPlaceholderText("Enter roll number")
        layout.addWidget(self.roll_input)

        layout.addSpacing(10)

        # Buttons
        btn_row = QHBoxLayout()
        ok_btn = QPushButton("Continue")
        ok_btn.setObjectName("success")
        ok_btn.clicked.connect(self._do_continue)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

    def _do_continue(self):
        name = self.name_input.text().strip()
        roll = self.roll_input.text().strip()

        if not name:
            QMessageBox.warning(self, "Input Error", "Please enter user name.")
            return
        if not roll:
            QMessageBox.warning(self, "Input Error", "Please enter roll number.")
            return

        self.name = name
        self.roll_number = roll
        self.accept()

# ─────────────────────────────────────────
# Allocation Dialog
# ─────────────────────────────────────────
class AllocationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Allocate Locker")
        self.setMinimumWidth(350)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowCloseButtonHint
        )
        self.user_name = None
        self.roll_number = None

        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QLineEdit   {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px; padding: 8px;
                font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover   { background: #45475a; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Allocate Locker")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)

        # Name input
        layout.addWidget(QLabel("User Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter user name")
        layout.addWidget(self.name_input)

        # Roll number input
        layout.addWidget(QLabel("Roll Number ID:"))
        self.roll_input = QLineEdit()
        self.roll_input.setPlaceholderText("Enter roll number")
        layout.addWidget(self.roll_input)

        layout.addSpacing(10)

        # Buttons
        btn_row = QHBoxLayout()
        allocate_btn = QPushButton("Allocate")
        allocate_btn.setObjectName("success")
        allocate_btn.clicked.connect(self._do_allocate)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(allocate_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

    def _do_allocate(self):
        name = self.name_input.text().strip()
        roll = self.roll_input.text().strip()

        if not name:
            QMessageBox.warning(self, "Input Error", "Please enter user name.")
            return
        if not roll:
            QMessageBox.warning(self, "Input Error", "Please enter roll number.")
            return

        self.user_name = name
        self.roll_number = roll
        self.accept()

# ─────────────────────────────────────────
# UID Dialog
# ─────────────────────────────────────────
class UIDDialog(QDialog):
    def __init__(self, title, get_uids, add_uid,
                 remove_uid, reset_uids, parent=None, locker_id=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowCloseButtonHint |
            Qt.WindowMinimizeButtonHint
        )
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        self._get_uids   = get_uids
        self._add_uid    = add_uid
        self._remove_uid = remove_uid
        self._reset_uids = reset_uids
        self.scanning    = False
        self.parent_win  = parent
        self.locker_id   = locker_id  # None for global cards, locker ID for locker dialogs
        self.pending_card_name = None  # For admin cards awaiting UID scan
        self.pending_card_roll = None

        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 13px; }
            QListWidget {
                background: #313244; color: #cdd6f4;
                border-radius: 6px; font-size: 12px; padding: 4px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover   { background: #45475a; }
            QPushButton#danger  { background: #f38ba8; color: #1e1e2e; }
            QPushButton#danger:hover  { background: #eb6c94; }
            QPushButton#success { background: #a6e3a1; color: #1e1e2e; }
            QPushButton#success:hover { background: #94d49b; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        hdr = QLabel(title)
        hdr.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(hdr)

        self.allocation_label = QLabel()
        self.allocation_label.setStyleSheet("color: #89b4fa; font-size: 12px; font-weight: bold;")
        self.allocation_label.hide()
        layout.addWidget(self.allocation_label)

        self.list_widget = QListWidget()
        self.list_widget.setMinimumHeight(120)
        layout.addWidget(self.list_widget)

        self.empty_label = QLabel(
            "Locker not allocated" if self.locker_id else "No UIDs assigned.\nAdd a card using the button below."
        )
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #6c7086; font-size: 12px;")
        layout.addWidget(self.empty_label)

        self.scan_label = QLabel("Tap a card on the admin scanner...")
        self.scan_label.setAlignment(Qt.AlignCenter)
        self.scan_label.setStyleSheet(
            "color: #a6e3a1; font-size: 13px; font-weight: bold;"
        )
        self.scan_label.hide()
        layout.addWidget(self.scan_label)

        btn_row = QHBoxLayout()

        self.add_btn = QPushButton("Allocate" if self.locker_id else "Add New Card")
        self.add_btn.setObjectName("success")
        self.add_btn.clicked.connect(
            self._handle_add_button if self.locker_id else self._handle_admin_add
        )

        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.clicked.connect(self.stop_scan)
        self.cancel_btn.hide()

        self.reset_btn = QPushButton("Reset")
        self.reset_btn.setObjectName("danger")
        self.reset_btn.clicked.connect(self._do_reset)

        self.open_btn = QPushButton("Open")
        self.open_btn.setObjectName("success")
        self.open_btn.clicked.connect(self._do_open)
        if not self.locker_id:
            self.open_btn.hide()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)

        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.open_btn)
        btn_row.addWidget(self.reset_btn)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        self._refresh()

    def _refresh(self):
        self.list_widget.clear()
        uids = self._get_uids()
        
        # Show/hide allocation details
        if self.locker_id and self.parent_win:
            alloc = self.parent_win.db.get_locker_allocation(self.locker_id)
            if alloc.get("name"):
                self.allocation_label.setText(
                    f"Name: {alloc['name']} | Roll #: {alloc['roll_number']}"
                )
                self.allocation_label.show()
            else:
                self.allocation_label.hide()
        
        if not uids:
            self.list_widget.hide()
            self.empty_label.show()
            # Show allocate button for empty locker, hide add button for global
            if self.locker_id:
                self.add_btn.setText("Allocate")
                self.add_btn.show()
            return
        # Locker is allocated, show "Add New Card" button
        if self.locker_id:
            self.add_btn.setText("Add New Card")
        self.empty_label.hide()
        self.list_widget.show()
        
        # For admin cards (global_uids), get details
        if not self.locker_id and self.parent_win:
            card_list = self.parent_win.db.get_global_uids_with_details()
            is_admin = True
        else:
            card_list = None
            is_admin = False
        
        for i, uid in enumerate(uids):
            container = QWidget()
            row       = QHBoxLayout(container)
            row.setContentsMargins(6, 4, 6, 4)
            row.setSpacing(8)
            
            # Create three columns for admin cards
            if is_admin and card_list and i < len(card_list):
                card_info = card_list[i]
                name = card_info.get("name", "")
                roll = card_info.get("roll_number", "")
                
                # Name column (140px width, wrappable)
                name_lbl = QLabel(name if name else "-")
                name_lbl.setStyleSheet("color: #cdd6f4;")
                name_lbl.setWordWrap(True)
                name_lbl.setFixedWidth(140)
                name_lbl.setAlignment(Qt.AlignTop | Qt.AlignLeft)
                
                # Roll # column (100px width)
                roll_lbl = QLabel(roll if roll else "-")
                roll_lbl.setStyleSheet("color: #cdd6f4;")
                roll_lbl.setFixedWidth(100)
                roll_lbl.setAlignment(Qt.AlignTop | Qt.AlignCenter)
                
                # UID column (flexible)
                uid_lbl = QLabel(uid)
                uid_lbl.setStyleSheet("color: #a6e3a1; font-family: monospace; font-size: 11px;")
                uid_lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                
                row.addWidget(name_lbl)
                row.addWidget(roll_lbl)
                row.addWidget(uid_lbl)
            else:
                # For locker cards or admin cards without details, just show UID
                uid_lbl = QLabel(uid)
                uid_lbl.setStyleSheet("color: #cdd6f4;")
                row.addWidget(uid_lbl)
            
            # Remove button
            rb = QPushButton("Remove")
            rb.setObjectName("danger")
            rb.setFixedWidth(72)
            rb.clicked.connect(lambda _, u=uid: self._do_remove(u))
            row.addStretch()
            row.addWidget(rb)
            
            item = QListWidgetItem()
            item.setSizeHint(container.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, container)

    def _handle_add_button(self):
        """Determine whether to allocate or add new card based on locker state."""
        uids = self._get_uids()
        if not uids:
            # Locker is empty, allocate it
            self._handle_allocate()
        else:
            # Locker is allocated, just add new card
            self.start_scan()

    def _handle_allocate(self):
        """Handle locker allocation when it's empty."""
        dialog = AllocationDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            # Save allocation details to database
            if self.parent_win and self.locker_id:
                self.parent_win.db.set_locker_allocation(
                    self.locker_id,
                    dialog.user_name,
                    dialog.roll_number
                )
            # Update display and start scan
            self._refresh()
            self.start_scan()
    
    def _handle_admin_add(self):
        """Handle adding card for admin cards with name and roll."""
        dialog = CardDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.pending_card_name = dialog.name
            self.pending_card_roll = dialog.roll_number
            self.start_scan()

    def start_scan(self):
        self.scanning = True
        self.scan_label.show()
        self.add_btn.hide()
        self.cancel_btn.show()
        if self.parent_win:
            self.parent_win.scan_target_dialog = self

    def stop_scan(self):
        self.scanning = False
        self.scan_label.hide()
        self.cancel_btn.hide()
        self.add_btn.show()
        if self.parent_win:
            self.parent_win.scan_target_dialog = None

    def receive_uid(self, uid):
        if not self.scanning:
            return
        
        # If this is an admin card with pending name/roll, save those details
        if not self.locker_id and self.pending_card_name:
            self._add_uid(uid)
            self.parent_win.db.update_global_uid_details(
                uid,
                self.pending_card_name,
                self.pending_card_roll
            )
            self.pending_card_name = None
            self.pending_card_roll = None
        else:
            self._add_uid(uid)

        # Confirm successful admin scan back to Pico
        if self.parent_win and self.parent_win.serial_worker:
            self.parent_win.serial_worker.send(f"{SECRET_KEY}:0:true")
        
        self.stop_scan()
        self._refresh()
        if self.parent_win:
            self.parent_win.update_locker_status()

    def _do_remove(self, uid):
        self._remove_uid(uid)
        self._refresh()
        if self.parent_win:
            self.parent_win.update_locker_status()

    def _do_open(self):
        """Manually open the locker by sending granted signal and logging with admin UID."""
        if not self.locker_id or not self.parent_win:
            return
        
        # Send granted command to pico
        if self.parent_win.serial_worker:
            self.parent_win.serial_worker.send(
                f"{SECRET_KEY}:{self.locker_id}:true"
            )
        
        # Log the action with "admin" as UID
        self.parent_win.logger.log(self.locker_id, "admin", "Granted")
        
        # Refresh log window if open
        if self.parent_win._log_window and not self.parent_win._log_window.isHidden():
            self.parent_win._log_window.refresh()

    def _do_reset(self):
        self._reset_uids()
        # Also clear allocation details for locker
        if self.parent_win and self.locker_id:
            self.parent_win.db.set_locker_allocation(self.locker_id, None, None)
        self._refresh()
        if self.parent_win:
            self.parent_win.update_locker_status()

    def closeEvent(self, event):
        self.stop_scan()   # always clean up scan state on close
        event.accept()

# ─────────────────────────────────────────
# Clear Logs Dialog
# ─────────────────────────────────────────
class ClearLogsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Clear Logs")
        self.setMinimumWidth(450)
        self.setModal(True)
        self.setWindowFlags(Qt.Window | Qt.WindowCloseButtonHint)
        
        self.mode = None
        self.value = None
        self.unit = None
        
        self.setStyleSheet("""
            QDialog     { background: #1e1e2e; color: #cdd6f4; }
            QLabel      { color: #cdd6f4; font-size: 12px; }
            QRadioButton { color: #cdd6f4; font-size: 12px; }
            QSpinBox, QComboBox {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px;
                padding: 6px; font-size: 12px;
            }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover { background: #45475a; }
            QPushButton#danger { background: #f38ba8; color: #1e1e2e; }
            QPushButton#danger:hover { background: #eb6c94; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)
        
        title = QLabel("Clear Logs")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        desc = QLabel("Choose what logs to delete:")
        desc.setStyleSheet("color: #a6e3a1; font-size: 11px;")
        layout.addWidget(desc)
        
        layout.addSpacing(12)
        
        # Option 1: Delete all
        self.rb_all = QRadioButton("Clear all logs")
        self.rb_all.setChecked(True)
        self.rb_all.toggled.connect(self._on_selection_changed)
        layout.addWidget(self.rb_all)
        
        layout.addSpacing(12)
        
        # Option 2: Delete older than X
        self.rb_older = QRadioButton("Delete logs OLDER than:")
        self.rb_older.toggled.connect(self._on_selection_changed)
        layout.addWidget(self.rb_older)
        
        older_row = QHBoxLayout()
        older_row.addSpacing(20)
        self.spin_older = QSpinBox()
        self.spin_older.setValue(30)
        self.spin_older.setMinimum(1)
        self.spin_older.setMaximum(9999)
        self.spin_older.setEnabled(False)
        older_row.addWidget(self.spin_older)
        
        self.combo_older = QComboBox()
        self.combo_older.addItems(["hours", "days", "months"])
        self.combo_older.setCurrentText("days")
        self.combo_older.setEnabled(False)
        older_row.addWidget(self.combo_older)
        
        older_row.addStretch()
        layout.addLayout(older_row)
        
        layout.addSpacing(12)
        
        # Option 3: Delete from last X
        self.rb_last = QRadioButton("Delete logs from the LAST:")
        self.rb_last.toggled.connect(self._on_selection_changed)
        layout.addWidget(self.rb_last)
        
        last_row = QHBoxLayout()
        last_row.addSpacing(20)
        self.spin_last = QSpinBox()
        self.spin_last.setValue(7)
        self.spin_last.setMinimum(1)
        self.spin_last.setMaximum(9999)
        self.spin_last.setEnabled(False)
        last_row.addWidget(self.spin_last)
        
        self.combo_last = QComboBox()
        self.combo_last.addItems(["hours", "days", "months"])
        self.combo_last.setCurrentText("days")
        self.combo_last.setEnabled(False)
        last_row.addWidget(self.combo_last)
        
        last_row.addStretch()
        layout.addLayout(last_row)
        
        layout.addSpacing(16)
        
        # Warning
        warning = QLabel("⚠ This action cannot be undone!")
        warning.setStyleSheet("color: #f38ba8; font-size: 11px; font-weight: bold;")
        layout.addWidget(warning)
        
        layout.addSpacing(8)
        
        # Buttons
        btn_row = QHBoxLayout()
        
        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("danger")
        delete_btn.clicked.connect(self._on_delete)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        btn_row.addStretch()
        btn_row.addWidget(delete_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)
    
    def _on_selection_changed(self):
        """Update spinbox/combo enabled states based on selection."""
        self.spin_older.setEnabled(self.rb_older.isChecked())
        self.combo_older.setEnabled(self.rb_older.isChecked())
        self.spin_last.setEnabled(self.rb_last.isChecked())
        self.combo_last.setEnabled(self.rb_last.isChecked())
    
    def _on_delete(self):
        """Store selected values and accept."""
        if self.rb_all.isChecked():
            self.mode = 'all'
            self.value = None
            self.unit = None
        elif self.rb_older.isChecked():
            self.mode = 'older_than'
            self.value = self.spin_older.value()
            self.unit = self.combo_older.currentText()
        else:  # rb_last
            self.mode = 'last'
            self.value = self.spin_last.value()
            self.unit = self.combo_last.currentText()
        
        self.accept()
    
    def get_params(self):
        """Return (mode, value, unit) tuple."""
        return (self.mode, self.value, self.unit)

# ─────────────────────────────────────────
# Log Window
# ─────────────────────────────────────────
class LogWindow(QDialog):
    def __init__(self, logger, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.setWindowTitle("Log History")
        self.setMinimumSize(760, 500)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowCloseButtonHint |
            Qt.WindowMinimizeButtonHint
        )

        self.setStyleSheet("""
            QDialog  { background: #1e1e2e; color: #cdd6f4; }
            QLabel   { color: #cdd6f4; font-size: 12px; }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 8px 14px; font-size: 12px;
            }
            QPushButton:hover  { background: #45475a; }
            QPushButton#danger { background: #f38ba8; color: #1e1e2e; }
            QComboBox, QDateEdit {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px; padding: 6px;
            }
            QTableWidget {
                background: #313244; color: #cdd6f4;
                border: none; gridline-color: #45475a;
            }
            QTableWidget::item {
                background: #313244; padding: 4px;
            }
            QTableWidget::item:alternate {
                background: #45475a;
            }
            QHeaderView::section {
                background: #45475a; color: #cdd6f4;
                padding: 6px; border: none; font-weight: bold;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("Log History")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)

        # Filters
        fl = QHBoxLayout()

        self.locker_filter = QComboBox()
        self.locker_filter.addItem("All Lockers")
        for i in range(1, LOCKER_COUNT + 1):
            self.locker_filter.addItem(f"Locker {i}")
        self.locker_filter.currentIndexChanged.connect(self._apply)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Status", "Granted", "Denied"])
        self.status_filter.currentIndexChanged.connect(self._apply)

        self.date_from = QDateEdit()
        self.date_from.setDate(QDate.currentDate().addMonths(-1))
        self.date_from.setCalendarPopup(True)
        self.date_from.dateChanged.connect(self._apply)

        self.date_to = QDateEdit()
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setCalendarPopup(True)
        self.date_to.dateChanged.connect(self._apply)

        fl.addWidget(QLabel("Locker:"))
        fl.addWidget(self.locker_filter)
        fl.addWidget(QLabel("Status:"))
        fl.addWidget(self.status_filter)
        fl.addWidget(QLabel("From:"))
        fl.addWidget(self.date_from)
        fl.addWidget(QLabel("To:"))
        fl.addWidget(self.date_to)
        fl.addStretch()
        layout.addLayout(fl)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Locker", "UID", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        bl = QHBoxLayout()
        clr = QPushButton("Clear Log")
        clr.setObjectName("danger")
        clr.clicked.connect(self._clear)
        cls = QPushButton("Close")
        cls.clicked.connect(self.close)
        bl.addWidget(clr)
        bl.addStretch()
        bl.addWidget(cls)
        layout.addLayout(bl)

        self._load()

    def _load(self):
        self.all_rows = list(reversed(self.logger.read_all()))
        self._apply()

    def refresh(self):
        self._load()

    def _apply(self):
        lf   = self.locker_filter.currentText()
        sf   = self.status_filter.currentText()
        dfrom = self.date_from.date().toString("yyyy-MM-dd")
        dto   = self.date_to.date().toString("yyyy-MM-dd")

        filtered = []
        for row in self.all_rows:
            if lf != "All Lockers":
                if row.get("locker_id", "") != lf.replace("Locker ", ""):
                    continue
            if sf != "All Status":
                if row.get("status", "") != sf:
                    continue
            ts = row.get("timestamp", "")
            if ts[:10] < dfrom or ts[:10] > dto:
                continue
            filtered.append(row)

        self.table.setRowCount(0)   # clear first
        self.table.setRowCount(len(filtered))
        for i, row in enumerate(filtered):
            self.table.setItem(
                i, 0, QTableWidgetItem(row.get("timestamp", ""))
            )
            self.table.setItem(
                i, 1,
                QTableWidgetItem(f"Locker {row.get('locker_id', '')}")
            )
            self.table.setItem(
                i, 2, QTableWidgetItem(row.get("uid", ""))
            )
            status = row.get("status", "")
            si = QTableWidgetItem(status)
            si.setForeground(
                QColor("#a6e3a1") if status == "Granted"
                else QColor("#f38ba8")
            )
            self.table.setItem(i, 3, si)

    def _clear(self):
        # Show the clear logs dialog
        dialog = ClearLogsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            mode, value, unit = dialog.get_params()
            
            # Build confirmation message
            if mode == 'all':
                summary = "Delete ALL logs?"
            elif mode == 'older_than':
                summary = f"Delete logs OLDER than {value} {unit}?"
            else:  # mode == 'last'
                summary = f"Delete logs from the LAST {value} {unit}?"
            
            # Show confirmation
            reply = QMessageBox.warning(
                self,
                "Confirm Deletion",
                f"{summary}\n\n⚠ This action cannot be undone!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Execute the deletion
                if mode == 'all':
                    self.logger.clear()
                else:
                    self.logger.clear_logs_by_time(mode, value, unit)
                
                # Refresh display by reloading logs from file
                self.refresh()
                QMessageBox.information(self, "Success", "Logs cleared successfully.")



# ─────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Locker System")
        icon_path = os.path.join(sys._MEIPASS, 'app.ico') if hasattr(sys, '_MEIPASS') else 'app.ico'
        self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(620, 440)

        self.db                 = Database()
        self.logger             = Logger()
        self.password_mgr       = PasswordManager()
        self.serial_worker      = None
        self.scan_target_dialog = None
        self._active_dialog     = None
        self._log_window        = None
        self.locker_buttons     = {}
        self.locker_status_labels = {}
        
        # Password session tracking (3 minutes)
        self.last_password_verify_time = None
        self.password_session_duration = 180  # 3 minutes in seconds
        
        # Check and set password on first launch
        if not self.password_mgr.password_exists():
            self._setup_initial_password()

        self.setStyleSheet("""
            QMainWindow, QWidget { background: #1e1e2e; color: #cdd6f4; }
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 8px;
                padding: 16px; font-size: 13px; font-weight: bold;
            }
            QPushButton:hover  { background: #45475a; }
            QPushButton#accent { background: #89b4fa; color: #1e1e2e; }
            QPushButton#accent:hover { background: #74a8f5; }
            QPushButton#small  {
                padding: 6px 10px; font-size: 12px;
                font-weight: normal;
            }
            QComboBox {
                background: #313244; color: #cdd6f4;
                border: none; border-radius: 6px;
                padding: 6px; min-width: 110px;
            }
            QLabel { color: #cdd6f4; }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        ml = QVBoxLayout(central)
        ml.setSpacing(14)
        ml.setContentsMargins(20, 20, 20, 20)

        # ── Top bar ──
        top = QHBoxLayout()
        title = QLabel("Locker System")
        title.setFont(QFont("Arial", 18, QFont.Bold))

        save_btn = QPushButton("Save Backup")
        save_btn.setObjectName("small")
        save_btn.clicked.connect(self._save_backup)

        load_btn = QPushButton("Load Backup")
        load_btn.setObjectName("small")
        load_btn.clicked.connect(self._load_backup)

        change_pwd_btn = QPushButton("Change Password")
        change_pwd_btn.setObjectName("small")
        change_pwd_btn.clicked.connect(self._change_password)

        factory_reset_btn = QPushButton("Factory Reset")
        factory_reset_btn.setObjectName("small")
        factory_reset_btn.setStyleSheet(factory_reset_btn.styleSheet() + """
            QPushButton { color: #f38ba8; }
        """)
        factory_reset_btn.clicked.connect(self._factory_reset)

        minimize_btn = QPushButton("Minimize to Tray")
        minimize_btn.setObjectName("small")
        minimize_btn.clicked.connect(self.minimize_to_tray)

        self.port_combo = QComboBox()
        self._refresh_ports()

        ref_btn = QPushButton("⟳")
        ref_btn.setObjectName("small")
        ref_btn.setFixedWidth(34)
        ref_btn.clicked.connect(self._refresh_ports)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("accent")
        self.connect_btn.setFixedWidth(110)
        self.connect_btn.clicked.connect(self._toggle_connection)

        self.status_lbl = QLabel("● Disconnected")
        self.status_lbl.setStyleSheet("color: #f38ba8; font-size: 12px;")

        top.addWidget(title)
        top.addWidget(save_btn)
        top.addWidget(load_btn)
        top.addWidget(change_pwd_btn)
        top.addWidget(factory_reset_btn)
        top.addWidget(minimize_btn)
        top.addStretch()
        top.addWidget(self.status_lbl)
        top.addSpacing(8)
        top.addWidget(self.port_combo)
        top.addWidget(ref_btn)
        top.addWidget(self.connect_btn)
        ml.addLayout(top)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background: #313244;")
        sep.setFixedHeight(1)
        ml.addWidget(sep)

        # ── Locker grid ──
        grid = QGridLayout()
        grid.setSpacing(10)
        for i in range(1, LOCKER_COUNT + 1):
            btn = QPushButton(f"Locker {i}")
            btn.setMinimumHeight(75)
            btn.clicked.connect(
                lambda _, lid=i: self._open_locker(lid)
            )
            self.locker_buttons[i] = btn

            status_label = QLabel("Available", btn)
            status_label.setStyleSheet("color: #a6e3a1; font-size: 12px; background: transparent;")
            status_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            status_label.setGeometry(5, 2, 80, 18)
            self.locker_status_labels[i] = status_label

            row = (i - 1) // 3
            col = (i - 1) % 3
            if i == 7:  # Center the 7th locker
                col = 1
            grid.addWidget(btn, row, col)
        ml.addLayout(grid)

        # ── Bottom bar ──
        bot = QHBoxLayout()
        adm_btn = QPushButton("Admin Cards")
        adm_btn.clicked.connect(self._open_global)

        log_btn = QPushButton("View Logs")
        log_btn.setObjectName("accent")
        log_btn.clicked.connect(self._open_logs)

        bot.addWidget(adm_btn)
        bot.addStretch()
        bot.addWidget(log_btn)
        ml.addLayout(bot)

        # ── Poll timer ──
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(50)

        # Auto-connect to COM5 if available
        self._refresh_ports()
        if 'COM5' in [p.device for p in serial.tools.list_ports.comports()]:
            self.port_combo.setCurrentText('COM5')
            self._toggle_connection()

        self.update_locker_status()

        # System tray setup
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        hide_action = tray_menu.addAction("Hide")
        hide_action.triggered.connect(self.hide)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(self.close)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    # ────────────────────────────────────
    def _poll(self):
        if self.serial_worker is None:
            return
        # check if thread died unexpectedly
        if not self.serial_worker.running:
            self._on_serial_error("Connection lost.")
            return
        processed = 0
        while processed < 20:
            try:
                line = self.serial_worker.q.get_nowait()
                self._process(line)
                processed += 1
            except queue.Empty:
                break

    def _process(self, line):
        print(f"RAW: {line}")

        if line.startswith("SERIAL_ERROR:"):
            self._on_serial_error(line.replace("SERIAL_ERROR:", ""))
            return

        if not line.startswith(SECRET_KEY + ":"):
            return

        parts = line.split(":")
        # minimum: KEY + index + at least one UID byte = 3 parts
        if len(parts) < 3:
            return

        try:
            idx = int(parts[1])
        except ValueError:
            return

        uid = ":".join(parts[2:])
        if not uid:
            return

        print(f"INDEX: {idx}  UID: {uid}")

        # index 0 = admin scanner, only feeds scan dialog
        if idx == 0:
            if self.scan_target_dialog is not None:
                self.scan_target_dialog.receive_uid(uid)
            return

        # locker matching
        matched = self.db.match_uid(idx, uid)
        status  = "Granted" if matched else "Denied"
        print(f"RESULT: {status}")

        # Visual feedback on locker button
        btn = self.locker_buttons.get(idx)
        if btn:
            color = "#a6e3a1" if matched else "#f38ba8"  # green for match, red for no match
            btn.setStyleSheet(f"background: {color};")
            QTimer.singleShot(250, lambda: btn.setStyleSheet(""))  # reset after 250ms

        self.logger.log(idx, uid, status)

        if self._log_window and not self._log_window.isHidden():
            self._log_window.refresh()

        self.serial_worker.send(
            f"{SECRET_KEY}:{idx}:{'true' if matched else 'false'}"
        )

    def _on_serial_error(self, msg):
        print(f"Serial error: {msg}")
        if self.serial_worker:
            self.serial_worker.stop()
            self.serial_worker = None
        self.status_lbl.setText("● Error — reconnect")
        self.status_lbl.setStyleSheet("color: #f38ba8; font-size: 12px;")
        self.connect_btn.setText("Connect")

    # ────────────────────────────────────
    def _refresh_ports(self):
        current = self.port_combo.currentText()
        self.port_combo.clear()
        for p in serial.tools.list_ports.comports():
            self.port_combo.addItem(p.device)
        # restore previous selection if still available
        idx = self.port_combo.findText(current)
        if idx >= 0:
            self.port_combo.setCurrentIndex(idx)

    def _toggle_connection(self):
        if self.serial_worker:
            self.serial_worker.stop()
            self.serial_worker = None
            self.status_lbl.setText("● Disconnected")
            self.status_lbl.setStyleSheet("color: #f38ba8; font-size: 12px;")
            self.connect_btn.setText("Connect")
        else:
            port = self.port_combo.currentText()
            if not port:
                QMessageBox.warning(self, "No Port", "No COM port selected.")
                return
            try:
                worker = SerialWorker(port)
                worker.start()
                self.serial_worker = worker
                self.status_lbl.setText("● Connected")
                self.status_lbl.setStyleSheet(
                    "color: #a6e3a1; font-size: 12px;"
                )
                self.connect_btn.setText("Disconnect")
            except Exception as e:
                QMessageBox.critical(
                    self, "Connection Error",
                    f"Could not open {port}:\n{e}"
                )

    # ────────────────────────────────────
    def update_locker_status(self):
        for i in range(1, LOCKER_COUNT + 1):
            uids = self.db.get_locker_uids(i)
            status = "Occupied" if uids else "Available"
            color = "#f38ba8" if uids else "#a6e3a1"  # red for occupied, green for available
            self.locker_status_labels[i].setText(status)
            self.locker_status_labels[i].setStyleSheet(f"color: {color}; font-size: 12px; background: transparent;")

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()

    def minimize_to_tray(self):
        self.hide()
        self.tray_icon.showMessage("Locker System", "Application minimized to tray.", QSystemTrayIcon.Information, 2000)

    def _open_locker(self, locker_id):
        if not self._verify_password():
            return
        if self._active_dialog and not self._active_dialog.isHidden():
            self._active_dialog.close()
        self._active_dialog = UIDDialog(
            title      = f"Locker {locker_id}",
            get_uids   = lambda: self.db.get_locker_uids(locker_id),
            add_uid    = lambda u: self.db.add_locker_uid(locker_id, u),
            remove_uid = lambda u: self.db.remove_locker_uid(locker_id, u),
            reset_uids = lambda: self.db.reset_locker(locker_id),
            parent     = self,
            locker_id  = locker_id
        )
        self._active_dialog.show()

    def _open_global(self):
        if not self._verify_password():
            return
        if self._active_dialog and not self._active_dialog.isHidden():
            self._active_dialog.close()
        self._active_dialog = UIDDialog(
            title      = "Admin Cards (opens any locker)",
            get_uids   = self.db.get_global_uids,
            add_uid    = self.db.add_global_uid,
            remove_uid = self.db.remove_global_uid,
            reset_uids = self.db.reset_global_uids,
            parent     = self
        )
        self._active_dialog.show()

    def _open_logs(self):
        if not self._verify_password():
            return
        if self._log_window and not self._log_window.isHidden():
            self._log_window.raise_()
            return
        self._log_window = LogWindow(self.logger, parent=self)
        self._log_window.show()

    def _save_backup(self):
        if not self._verify_password():
            return
        from PyQt5.QtWidgets import QFileDialog
        import zipfile
        fname, _ = QFileDialog.getSaveFileName(self, "Save Backup", "", "Backup Files (*.zip)")
        if fname:
            try:
                with zipfile.ZipFile(fname, 'w') as zf:
                    zf.write(DB_FILE, 'lockers.json')
                    zf.write(LOG_FILE, 'locker_log.csv')
                QMessageBox.information(self, "Success", "Backup saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save backup: {e}")

    def _load_backup(self):
        if not self._verify_password():
            return
        from PyQt5.QtWidgets import QFileDialog
        import zipfile
        fname, _ = QFileDialog.getOpenFileName(self, "Load Backup", "", "Backup Files (*.zip)")
        if fname:
            try:
                with zipfile.ZipFile(fname, 'r') as zf:
                    zf.extract('lockers.json', '.')
                    zf.extract('locker_log.csv', '.')
                self.db = Database()  # reload database
                self.logger = Logger()  # reload logger
                if self._log_window and not self._log_window.isHidden():
                    self._log_window.refresh()
                self.update_locker_status()
                QMessageBox.information(self, "Success", "Backup loaded successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load backup: {e}")

    def _setup_initial_password(self):
        """Show password setup dialog on first launch."""
        dialog = SetPasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.password
            if self.password_mgr.set_password(password):
                QMessageBox.information(self, "Success", "Password set successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to set password.")
        else:
            # User cancelled - close the app
            self.close()

    def _verify_password_on_startup(self):
        """Verify password on app startup."""
        max_attempts = 3
        attempts = 0
        while attempts < max_attempts:
            dialog = VerifyPasswordDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                password = dialog.get_password()
                if self.password_mgr.verify_password(password):
                    return True
                else:
                    attempts += 1
                    remaining = max_attempts - attempts
                    if remaining > 0:
                        QMessageBox.warning(self, "Wrong Password", f"Password incorrect. {remaining} attempts remaining.")
                    else:
                        QMessageBox.critical(self, "Access Denied", "Maximum password attempts exceeded. Closing application.")
                        self.close()
                        return False
            else:
                # User cancelled
                self.close()
                return False
        return False

    def _verify_password(self):
        """Verify password before sensitive operations with session caching."""
        # Check if we're still within the password session window
        if self.last_password_verify_time is not None:
            elapsed = time.time() - self.last_password_verify_time
            if elapsed < self.password_session_duration:
                # Still within session - grant access
                remaining = int(self.password_session_duration - elapsed)
                print(f"[SESSION] Password session still valid. {remaining}s remaining.")
                return True
            else:
                # Session expired
                print(f"[SESSION] Password session expired after {elapsed:.0f}s")
        
        # Ask for password
        dialog = VerifyPasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.get_password()
            if self.password_mgr.verify_password(password):
                # Update session timestamp
                self.last_password_verify_time = time.time()
                print(f"[SESSION] Password verified. Session started (3 minutes).")
                return True
            else:
                QMessageBox.warning(self, "Wrong Password", "Password is incorrect.")
                return False
        return False

    def _change_password(self):
        """Change the master password."""
        # First verify current password
        dialog = VerifyPasswordDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        
        password = dialog.get_password()
        if not self.password_mgr.verify_password(password):
            QMessageBox.warning(self, "Wrong Password", "Current password is incorrect.")
            return
        
        # Now ask for new password
        new_pwd_dialog = ChangePasswordDialog(self)
        if new_pwd_dialog.exec_() == QDialog.Accepted:
            new_password = new_pwd_dialog.get_new_password()
            if self.password_mgr.set_password(new_password):
                # Reset session since password changed
                self.last_password_verify_time = None
                QMessageBox.information(self, "Success", "Password changed successfully.")
            else:
                QMessageBox.critical(self, "Error", "Failed to change password.")

    def _factory_reset(self):
        """Factory reset: delete all data and restart app."""
        # Show multiple confirmation dialogs
        reply = QMessageBox.warning(
            self,
            "Factory Reset",
            "⚠ WARNING: This will DELETE ALL DATA!\n\n"
            "This will erase:\n"
            "  • All locker configurations\n"
            "  • All access logs\n"
            "  • Master password\n\n"
            "The application will restart as if loading for the first time.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        # Second confirmation
        reply2 = QMessageBox.critical(
            self,
            "Are You Sure?",
            "This action CANNOT be undone!\n\nClick YES to proceed with factory reset.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply2 == QMessageBox.No:
            return
        
        # Proceed with factory reset
        try:
            # Delete database file
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
                print(f"[RESET] Deleted {DB_FILE}")
            
            # Delete log file
            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)
                print(f"[RESET] Deleted {LOG_FILE}")
            
            # Delete password file
            if os.path.exists(PASSWORD_FILE):
                os.remove(PASSWORD_FILE)
                print(f"[RESET] Deleted {PASSWORD_FILE}")
            
            print("[RESET] Factory reset complete. Restarting application...")
            
            # Close all windows
            if self._log_window:
                self._log_window.close()
            if self._active_dialog:
                self._active_dialog.close()
            
            # Restart the application
            QApplication.quit()
            import subprocess
            subprocess.Popen([sys.executable, __file__])
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Factory reset failed: {e}")
            print(f"[RESET] Error: {e}")

    def closeEvent(self, event):
        self._timer.stop()
        if self.serial_worker:
            self.serial_worker.stop()
        event.accept()

# ─────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.showMaximized()
    sys.exit(app.exec_())