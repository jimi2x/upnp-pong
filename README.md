<h1> upnp-pong.py </h1>
<p><strong>uPNP Pong</strong> is a free Linux/Unix security discovery & threat hunting tool (Python3 script) that performs uPNP host and services discovery on your local network and sniffs all IPv4 & IPv6 <strong>UDP:1900</strong> traffic.</p>

## Original script
<strong>jimi2x</strong>

---
## Functions
* **IPv4/IPv6 Enumeration of uPNP/SSDP hosts in local network**
* **OUI Lookups for MACs**
* **Discovered services logging**
* **URL Discovery (WWW/XML)**
* **CSV export of all captured data (outputs 'SSDP_LOG.csv' in local directory**

---
## Quick install notes:
```
pip3 install mac_vendor_lookup
pip3 install scapy
```

---
## Example Usage (run as root):
```
chmod 755 upnp-pong.py
sudo python3 upnp-pong.py

Mash CTRL-C to quit.
```
---
## License
MIT License
