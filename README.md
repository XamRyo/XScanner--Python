# Network Port Scanner Documentation  

This Python script performs a **network port scan** using the `nmap` library to identify open ports on a target IP address. Below is a detailed breakdown of its functionality.  

---

## **1. Table of Contents**  
1. **Introduction**  
2. **Features**  
3. **Dependencies**  
4. **Usage**  
5. **Code Explanation**  
6. **Sample Output**  
7. **Security & Ethical Considerations**  
8. **Limitations**  
9. **Future Improvements**  
10. **Conclusion**  

---

## **2. Features**  
- Scans a target IP address for open ports  
- Provides:  
  - IP status (up/down)  
  - Protocol(s) in use (TCP/UDP)  
  - Open ports and their states (open/filtered/closed)  
- Uses `nmap` for reliable scanning  
- Simple command-line input-based execution  

---

## **3. Dependencies**  
- **Python 3.6+**  
- **Nmap Python Library** (`python-nmap`)  
  - Install via pip:  
    ```bash
    pip install python-nmap
    ```
  - (Optional) Install Nmap itself for advanced scanning:  
    ```bash
    sudo apt-get install nmap  # Linux/Unix
    ```
  
---

## **4. Usage**  

### **Running the Script**  
```bash
python port_scanner.py
```
**Interactive Input:**  
```plaintext
[+] Target IP ==> [INPUT YOUR TARGET IP HERE]
```
Example output:  

```plaintext
Host : 192.1xx.x.x  
State : up  
Protocol : tcp  

port : 22    state : open  
port : 80    state : open  
port : 443   state : open  

Open Ports: -p 22,80,443 192.168.1.1
```

---

## **5. Code Breakdown**  

### **Critical Script Sections:**  

#### **A. Initialization & nmap Setup**  
```python
import nmap

nm = nmap.PortScanner()  # Create Nmap scanner object
open_ports = "-p "       # Will store open ports in Nmap format (e.g., "-p 80,443")
```

#### **B. Banner & User Input**  
```python
print("[Info] This is a PortScanner to scan open ports on a target IP address.")
print("  || Uses NMAP (network mapper) library for Python 3.")

target_ip = input("[+] Target IP ==> ")  # Prompt user for IP
```

#### **C. Execute Port Scan**  
```python
scan_results = nm.scan(
    hosts=target_ip,
    arguments="-sT -n -Pn -T4"
)
```
**Scan Arguments Explained:**  
| Flag | Explanation |  
|------|-------------|  
| `-sT`  | **TCP Connect Scan**: Reliable, but detectable (3-way handshake) |  
| `-n`   | **No DNS resolution**: Faster scan (skips hostname lookup) |  
| `-Pn`  | **No Ping**: Bypasses host discovery (assumes host is up) |  
| `-T4`  | **Timing Aggressiveness**: Faster scan (higher values risk detection) |  

#### **D. Output Host Status & Protocols**  
```python
print("\nHost : %s" % target_ip)  
print("State : %s" % nm[target_ip].state())  

for protocol in nm[target_ip].all_protocols():  
    print("Protocol : %s" % protocol)  
    for port in nm[target_ip][protocol].keys():  
        print("port : %s\tstate : %s" % (port, nm[target_ip][protocol][port]["state"]))  
```

#### **E. Store Open Ports in a Nmap-Friendly Format**  
```python
count = 0  
for port in nm[target_ip][protocol].keys():  
    if nm[target_ip][protocol][port]["state"] == "open":  
        if count == 0:  
            open_ports += str(port)  
            count = 1  
        else:  
            open_ports += "," + str(port)  

print("\nOpen Ports: " + open_ports + " " + target_ip)  
```

---

## **6. Security & Ethical Considerations**  
- ⚠️ **Legal Issues**: Unauthorized scanning is illegal in many jurisdictions. Always obtain permission before scanning.  
- ⚠️ **Detection Risks**: Using `-sT` (full TCP handshake) makes the scan more detectable.  
- ✅ **Use Cases**:  
  - **Network admins** verifying firewall rules  
  - **Security audits** (when authorized)  
  - **Pen-testing** exercises  
- ⛔ **Do Not Use** for:    
  - Malicious purposes  
  - Scanning networks without consent  

---

## **7. Possible Enhancements**  
1. **Add UDP Scanning**  
   ```bash
   nm.scan(hosts=target_ip, arguments="-sU -sS")
   ```
2. **OS & Version Detection**  
   ```bash
   nm.scan(hosts=target_ip, arguments="-O -sV") 
   ```
3. **Output to File (CSV/JSON)**  
   ```python
   with open("scan_results.json", "w") as f: 
       json.dump(scan_results, f) 
   ```
4. **Multi-IP / Subnet Scanning**  
   ```python
   target_ip = "192.1xx.x.x/24"  # Scan entire subnet 
   ```

---

## **8. Conclusion**  
This script provides a **basic yet effective** way to scan a network for open ports using Python and Nmap. Enhancements can make it more flexible for **security professionals** and **network administrators**.  
