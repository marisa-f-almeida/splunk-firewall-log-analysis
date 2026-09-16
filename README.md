# SIEM Lab: Network Firewall Traffic & Port Security Analysis (Splunk)

An enterprise-grade network security monitoring architecture implemented within **Splunk Cloud (Dashboard Studio)**. This project simulates corporate firewall traffic logs to track access patterns, detect port scanning activity, and analyze unauthorized network connections.

---

## 🔍 Lab Overview & Investigative Logic

This deployment processes continuous firewall transaction entries to isolate anomalous traffic vectors and evaluate edge network perimeter defense efficiency:

1. **Traffic Ingestion & Segmentation**: Normalizes network data rows categorized into explicit actions (`action="allow"` vs. `action="deny"`).
2. **Port Vulnerability Mapping**: Monitors connections across high-risk application ports, including **22 (SSH)**, **80/443 (HTTP/S)**, and **3389 (RDP)** to flag baseline anomalies.
3. **Geo-Location & Inbound Risk Analysis**: Structures network traffic metadata into grouped analytics ready for real-time dashboard visualization.

---
<img width="1440" height="900" alt="Screen Shot 2026-09-15 at 8 24 21 PM" src="https://github.com/user-attachments/assets/2a9f4f90-116b-4cf6-84e2-65e895ffb3b3" />

## 💻 Core SPL Analysis Framework

```splunk
| makeresults count=80
| streamstats count as row
| eval time_offset = row * 15
| eval _time = _time - time_offset
| eval ip_idx = case(row <= 20, 0, row <= 45, 1, row <= 65, 2, 1=1, 3)
| eval src_ip = mvindex(split("185.220.101.5,45.89.23.11,10.0.0.5,192.168.1.100", ","), ip_idx)
| eval dest_port_idx = row % 4
| eval dest_port = mvindex(split("443,22,3389,80", ","), dest_port_idx)
| eval action_idx = case(src_ip=="185.220.101.5", 1, src_ip=="45.89.23.11", 1, 1=1, 0)
| eval firewall_action = mvindex(split("allow,deny", ","), action_idx)
| stats count by src_ip, dest_port, firewall_action
| sort - count
| rename src_ip as "Source IP", dest_port as "Destination Port", firewall_action as "Firewall Action", count as "Total Connections"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout System)
- **Primary Interface Theme**: SOC dark operational theme
- **Core Visual Element**: Multi-dimensional Network Security Data Table
- **Monitored Indicators (IoCs)**: Attacker Network Footprint, Targeted Network Entry point, Perimeter Action, Volumetric Traffic Count.
