# Network Diagnostic Scanner

This is a network diagnostic tool that helps users scan their local network for connected devices. It supports multiple scanning methods, including ICMP ping, ARP scan, and TCP SYN. The application also allows users to register new devices and retrieve detailed information such as IP addresses, MAC addresses, TTL (Time To Live), and detected operating systems.

## Features

- **Scan Devices in a Network**: Supports ICMP ping, ARP scan, and TCP SYN to detect devices.
- **Device Registration**: Allows users to register devices by adding their IP and MAC addresses.
- **OS Detection**: Based on TTL values, the application attempts to determine the operating system of detected devices.
- **Background Threading**: Runs network operations in the background to prevent UI freezing.
- **Real-Time Updates**: Displays the results of the scan in real-time.

## Prerequisites

- Python 3.x
- PyQt5 (for GUI)
- Scapy (for network scanning)

## Installation

1. Clone this repository:
   ```bash
   git clone git@github.com:le01s/network_scanner.git
   cd network_scanner
   ```

2. Install dependencies:
   ```bash
    pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
    python main.py
   ```
   
## Code Structure

### 1. **Functions**:

- **`get_ttl(host)`**:
    - Description: Executes a ping command to the specified host and extracts the TTL (Time To Live) from the response. TTL is used to determine the operating system of the device.
    - Parameters:
        - `host`: The IP address of the host to ping.
    - Returns: TTL (integer) or `None` if no response was received.

- **`get_mac(ip)`**:
    - Description: Sends an ARP request to obtain the MAC address of the device by its IP address.
    - Parameters:
        - `ip`: The IP address of the device.
    - Returns: The MAC address of the device (string) or `None` if the device did not respond to the ARP request.

- **`determine_os(ttl)`**:
    - Description: Determines the operating system of a device based on its TTL. This works by matching known TTL values for different operating systems.
    - Parameters:
        - `ttl`: The TTL value of the device, obtained from `get_ttl()`.
    - Returns: A string representing the device's operating system (e.g., "Linux/Unix", "Windows", "Router/Server") or "Unknown" if the TTL is not recognized.

- **`scan_network(network, mask, method, known_devices, update_callback)`**:
    - Description: The main function for network scanning. It uses the specified scanning method (ICMP Ping, ARP Scan, or TCP SYN) and displays the results for each device on the network.
    - Parameters:
        - `network`: The network IP address.
        - `mask`: The network mask (e.g., `24`).
        - `method`: The scanning method (ICMP Ping, ARP Scan, TCP SYN).
        - `known_devices`: A dictionary of registered devices (IP address -> MAC address).
        - `update_callback`: A callback function to update the UI with scan results.
    - Returns: None. The function sends results to the user interface via the callback.

### 2. **Classes**:

- **`RegistrationDialog`**:
    - Description: A dialog window for registering a new device in the system, allowing the user to input the device's IP and MAC address.
    - Key Methods:
        - **`__init__()`**: Initializes the registration dialog.
        - **`register_device()`**: Registers the device by adding its IP and MAC addresses to the list of known devices.

- **`ScanThread`**:
    - Description: A thread for performing network scanning. It runs in the background without blocking the main UI thread.
    - Key Methods:
        - **`__init__()`**: Initializes the scan thread with parameters for scanning.
        - **`run()`**: Executes the scanning process and passes results via the `update_signal`.

- **`NetworkScanner`**:
    - Description: The main window of the application, providing the interface for interacting with the user.
    - Key Methods:
        - **`__init__()`**: Initializes the user interface components.
        - **`init_ui()`**: Sets up the layout and widgets of the UI (buttons, input fields, combo box).
        - **`run_scan()`**: Starts the scanning process by passing parameters to the `ScanThread`.
        - **`update_results()`**: Updates the text field with the results of the scan.
        - **`open_registration_dialog()`**: Opens the registration dialog to add a new device.

### 3. **Graphical Interface**:

The main interface consists of the following elements:

- **IP Range Input Field**:
    - For specifying the range of IP addresses to be scanned, e.g., `192.168.1.0`.
  
- **Network Mask Input Field**:
    - For specifying the network mask, e.g., `24`, to scan the `192.168.1.0/24` subnet.
  
- **ComboBox**:
    - For selecting the scanning method:
        - ICMP Ping
        - ARP Scan
        - TCP SYN

- **"Scan" Button**:
    - Starts the network scan with the selected parameters.

- **"Register Device" Button**:
    - Opens the dialog to register a new device by entering its IP and MAC addresses.

- **Text Field (QTextEdit)**:
    - Displays the scan results in real-time.

### 4. **Threading**:

The application uses threads to perform network operations in the background. This allows the user interface to remain responsive while the scan is running. The `ScanThread` thread performs the scan and sends the results back to the main thread via the `update_signal` for UI updates.

## Example Usage

1. **Launching the Program**:
    - After starting the application, enter the IP range you wish to scan (e.g., `192.168.1.0`).
    - Enter the network mask, e.g., `24`, to scan the `192.168.1.0/24` subnet.
    - Select the scan method:
        - **ICMP Ping**: Check if the device is reachable via ping.
        - **ARP Scan**: Get the MAC addresses of devices.
        - **TCP SYN**: Check if port 80 is open on devices.
    - Click the "Scan" button to start scanning.

2. **Registering a New Device**:
    - Click the "Register Device" button to open the registration dialog.
    - Enter the IP and MAC address of the device and click "Register."
    - The registered device will be displayed in the list.

3. **Viewing Results**:
    - Scan results will be displayed in the text field. Each detected host will show its IP address, MAC address, and status, as well as the TTL and detected operating system (if available).
