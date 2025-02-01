import ipaddress
import subprocess
import scapy.all as scapy
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QComboBox, QLineEdit, QLabel, \
    QDialog, QFormLayout
from PyQt6.QtCore import pyqtSignal, QThread
import sys


def get_ttl(host):
    try:
        proc = subprocess.Popen(["ping", "-c", "1", "-W", "1", host], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = proc.communicate()[0].decode()
        for line in output.split("\n"):
            if "ttl=" in line:
                ttl = int(line.split("ttl=")[1].split()[0])
                return ttl
    except Exception as e:
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


def scan_network(network, mask, method, known_devices, update_callback):
    network = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)

    for ip in network.hosts():  # Используем метод .hosts() для итерации по хостам сети
        ip = str(ip)
        mac = get_mac(ip)  # Получаем MAC-адрес для каждого устройства

        if method == "ICMP Ping":
            ttl = get_ttl(ip)
            os = determine_os(ttl)
            if ttl is not None:
                status = "(НЕИЗВЕСТНОЕ УСТРОЙСТВО!)" if ip not in known_devices else "(Зарегистрировано)"
                result = f"{ip} - TTL: {ttl} - ОС: {os} - {status}"
                update_callback(result)

        elif method == "ARP Scan":
            arp_req = scapy.ARP(pdst=ip)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_req
            response = scapy.srp(packet, timeout=1, verbose=False)[0]
            if response:
                mac = response[0][1].hwsrc
                status = "(НЕИЗВЕСТНОЕ УСТРОЙСТВО!)" if mac not in known_devices.values() else "(Зарегистрировано)"
                result = f"{ip} - MAC: {mac} {status}"
                update_callback(result)

        elif method == "TCP SYN":
            syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=False)
            if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 18:
                status = "(НЕИЗВЕСТНОЕ УСТРОЙСТВО!)" if ip not in known_devices else "(Зарегистрировано)"
                result = f"{ip} - Открыт порт 80 - MAC: {mac} {status}"
                update_callback(result)


class RegistrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Регистрация устройства")
        self.setGeometry(300, 300, 300, 150)

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
            self.parent().known_devices[ip] = mac
            self.accept()


class ScanThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, network, mask, method, known_devices):
        super().__init__()
        self.network = network
        self.mask = mask
        self.method = method
        self.known_devices = known_devices

    def run(self):
        scan_network(self.network, self.mask, self.method, self.known_devices, self.update_signal.emit)


class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.known_devices = {"192.168.1.100": "AA:BB:CC:DD:EE:FF"}
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
        self.setWindowTitle("Диагностический сканер сети")
        self.setGeometry(200, 200, 500, 400)

    def run_scan(self):
        self.result_text.setText("Начинаю сканирование...")

        network = self.input_field.text()
        mask = self.mask_input.text()
        method = self.method_combo.currentText()

        self.scan_thread = ScanThread(network, mask, method, self.known_devices)
        self.scan_thread.update_signal.connect(self.update_results)
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
