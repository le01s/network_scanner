import ipaddress
import subprocess
import sqlite3
import scapy.all as scapy
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QComboBox, QLineEdit, QLabel, \
    QDialog, QFormLayout
from PyQt6.QtCore import pyqtSignal, QThread
import sys

def get_ttl(host):
    try:
        # Для Windows используем другую команду ping
        proc = subprocess.run(["ping", "-n", "1", "-w", "1000", host], capture_output=True, text=True)
        output = proc.stdout
        for line in output.split("\n"):
            if "TTL=" in line:  # Для Windows TTL в верхнем регистре
                ttl = int(line.split("TTL=")[1].split()[0])
                return ttl
    except Exception:
        return None

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    response = scapy.srp(packet, timeout=1, verbose=False)[0]
    if response:
        return response[0][1].hwsrc
    return None

def determine_os(ttl):
    if ttl is None:
        return "Неизвестно"
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Маршрутизатор/Сервер"

def check_anonymous_ports(ip):
    anonymous_ports = [9050, 9150, 1080]
    for port in anonymous_ports:
        syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(syn_packet, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 18:
            return f"Анонимный порт {port} открыт!"
    return "Анонимные порты закрыты."

def scan_network(network, mask, method, known_devices, update_callback):
    network = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    for ip in network.hosts():
        ip = str(ip)
        mac = get_mac(ip)
        if method == "ICMP Ping":
            ttl = get_ttl(ip)
            os = determine_os(ttl)
            if ttl is not None:
                status = "(НЕИЗВЕСТНОЕ УСТРОЙСТВО!)" if ip not in known_devices else "(Зарегистрировано)"
                anon_check = check_anonymous_ports(ip)
                result = f"{ip} - TTL: {ttl} - ОС: {os} - {status} - {anon_check}"
                update_callback(result)

def init_db():
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            mac TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT,
            mask TEXT,
            method TEXT,
            result TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan_history(network, mask, method, result):
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_history (network, mask, method, result) VALUES (?, ?, ?, ?)", 
                   (network, mask, method, result))
    conn.commit()
    conn.close()

def load_scan_history():
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("SELECT network, mask, method, result, timestamp FROM scan_history ORDER BY timestamp DESC")
    history = cursor.fetchall()
    conn.close()
    return history

def register_device(ip, mac):
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO devices (ip, mac) VALUES (?, ?)", (ip, mac))
    conn.commit()
    conn.close()

def load_known_devices():
    conn = sqlite3.connect("devices.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip, mac FROM devices")
    devices = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return devices

class RegistrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Регистрация устройства")
        layout = QFormLayout()
        self.ip_input = QLineEdit()
        self.mac_input = QLineEdit()
        layout.addRow("IP-адрес:", self.ip_input)
        layout.addRow("MAC-адрес:", self.mac_input)
        self.register_button = QPushButton("Зарегистрировать")
        self.register_button.clicked.connect(self.register_device)
        layout.addRow(self.register_button)
        self.setLayout(layout)
    
    def register_device(self):
        ip = self.ip_input.text()
        mac = self.mac_input.text()
        if ip and mac:
            register_device(ip, mac)
            self.accept()

class ScanThread(QThread):
    result_signal = pyqtSignal(str)

    def __init__(self, network, mask, method, known_devices):
        super().__init__()
        self.network = network
        self.mask = mask
        self.method = method
        self.known_devices = known_devices

    def run(self):
        scan_network(self.network, self.mask, self.method, self.known_devices, self.emit_result)

    def emit_result(self, result):
        self.result_signal.emit(result)

class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        init_db()
        self.known_devices = load_known_devices()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.label = QLabel("Введите диапазон (например, 192.168.1.0)")
        layout.addWidget(self.label)
        self.input_field = QLineEdit()
        layout.addWidget(self.input_field)
        self.mask_input = QLineEdit("24")
        layout.addWidget(self.mask_input)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["ICMP Ping", "ARP Scan", "TCP SYN"])
        layout.addWidget(self.method_combo)
        self.scan_button = QPushButton("Сканировать")
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button)
        self.register_button = QPushButton("Зарегистрировать устройство")
        self.register_button.clicked.connect(self.open_registration_dialog)
        layout.addWidget(self.register_button)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        self.setLayout(layout)

    def run_scan(self):
        self.result_text.setText("Начинаю сканирование...")
        network = self.input_field.text()
        mask = self.mask_input.text()
        method = self.method_combo.currentText()

        # Создаем и запускаем поток сканирования
        self.scan_thread = ScanThread(network, mask, method, self.known_devices)
        self.scan_thread.result_signal.connect(self.update_results)
        self.scan_thread.start()

    def update_results(self, result):
        self.result_text.append(result)

    def open_registration_dialog(self):
        dialog = RegistrationDialog(self)
        if dialog.exec() == QDialog.accept:
            self.result_text.append(f"Устройство {dialog.ip_input.text()} зарегистрировано.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = NetworkScanner()
    scanner.show()
    sys.exit(app.exec())