# 🔍 KeyloggerDetector — Python Edition

**Author:** hemanathan115  
**Version:** 1.0  
**Language:** Python 3.7+  
**Platforms:** Windows & Linux

---

## 📌 What It Does

KeyloggerDetector scans your system for signs of keylogger or spyware activity:

| Check | Windows | Linux |
|---|---|---|
| Suspicious process names | ✅ | ✅ |
| Suspicious DLL / hook injection | ✅ | — |
| Registry startup entries | ✅ | — |
| Kernel module scan | — | ✅ |
| Hidden drop paths | — | ✅ |
| Suspicious network connections | ✅ | ✅ |
| High-CPU background programs | ✅ | ✅ |

---

## ⚙️ Requirements

```bash
pip install psutil
```

> `psutil` is auto-installed if missing when you run the script.

---

## 🚀 Usage

```bash
python keylogger_detector.py
```

> **Windows:** Run as Administrator for full registry + DLL scanning.  
> **Linux:** Run as root (`sudo`) for kernel module access.

---

## 📊 Output Example

```
╔══════════════════════════════════════════════════════╗
║         KeyloggerDetector v1.0  — Python Edition     ║
╚══════════════════════════════════════════════════════╝

[*] Scanning running processes...
[2024-01-01 12:00:00] [!!!] CRITICAL ALERT >> Suspicious process: PID=4821 | Name=keylogger.exe

[*] Scanning network connections...
[2024-01-01 12:00:01] [!]   WARNING       >> Suspicious outbound connection: PID=4821 -> 192.168.1.5:4444

════════════════════════
  SCAN SUMMARY
  Critical : 1
  Warnings : 1
════════════════════════
```

---

## 📁 Project Structure

```
KeyloggerDetector/
├── keylogger_detector.py   ← Main script
└── README.md               ← This file
```

---

## ⚠️ Disclaimer

This tool is for **educational and defensive security purposes only**.  
Use only on systems you own or have explicit permission to scan.

---

## 📜 License

MIT License — free to use, modify, and distribute.
