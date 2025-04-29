import sys
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QPushButton, QWidget, QMessageBox
)
from PyQt5.QtGui import QIcon  # Import for setting the window icon

# Supabase Configuration
SUPABASE_URL = "" # Insert your Supabase URL here
SUPABASE_API_KEY = "" # Insert your Supabase API key here

headers = {
    "apikey": SUPABASE_API_KEY,
    "Authorization": f"Bearer {SUPABASE_API_KEY}"
}

class AdminApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Vanguard Admin Panel")
        self.setGeometry(100, 100, 800, 400)
        self.setWindowIcon(QIcon("app_icon.ico"))  # Set the custom icon

        # Main Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout
        self.layout = QVBoxLayout(self.central_widget)

        # Table for Logs
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Device", "MAC Address", "Alert", "Timestamp"])
        self.layout.addWidget(self.table)

        # Fetch Logs Button
        self.fetch_logs_button = QPushButton("Fetch Logs")
        self.fetch_logs_button.clicked.connect(self.fetch_logs)
        self.layout.addWidget(self.fetch_logs_button)

    def fetch_logs(self):
        """Fetch logs from Supabase and display in the table."""
        try:
            response = requests.get(f"{SUPABASE_URL}/rest/v1/usb_logs", headers=headers)
            if response.status_code == 200:
                logs = response.json()
                self.display_logs(logs)
            else:
                QMessageBox.critical(self, "Error", f"Failed to fetch logs: {response.status_code}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def display_logs(self, logs):
        """Display logs in the table."""
        self.table.setRowCount(len(logs))
        for row, log in enumerate(logs):
            self.table.setItem(row, 0, QTableWidgetItem(str(log.get("id", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(log.get("device", "")))
            self.table.setItem(row, 2, QTableWidgetItem(log.get("mac_address", "")))
            self.table.setItem(row, 3, QTableWidgetItem(log.get("alert", "")))
            self.table.setItem(row, 4, QTableWidgetItem(log.get("timestamp", "")))

# Run the Application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AdminApp()
    window.show()
    sys.exit(app.exec_())
