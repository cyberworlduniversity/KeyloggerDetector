"""
KeyloggerDetector v1.0 - Python Edition
github.com/hemanathan115

Detects possible keylogger programs running on the system.
Checks: Suspicious processes, keyboard hooks, unknown background programs.
Supports: Windows & Linux
"""

import os
import sys
import platform
import datetime
import subprocess

try:
    import psutil
except ImportError:
    print("[!] psutil not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

# ─────────────────────────────────────────────
# Suspicious process/file name signatures
# ─────────────────────────────────────────────
SUSPICIOUS_NAMES = [
    "keylog", "klogger", "spyware", "hookmon",
    "keyhook", "keyspy", "logkeys", "k9logger",
    "revealer", "refog", "kidlogger", "actualspy",
    "ardamax", "elite_keylogger", "blackbox",
    "ghostkeylogger", "snifferspy", "stealthlogger",
    "perfect_keylogger", "iwantsoft", "spyrix",
    "typingspy", "allinneed", "loginspector"
]

# ─────────────────────────────────────────────
# Alert levels
# ─────────────────────────────────────────────
ALERTS = []

def alert(level: str, message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    icons = {"CRITICAL": "[!!!]", "WARNING": "[!]  ", "INFO": "[*]  "}
    labels = {"CRITICAL": "CRITICAL ALERT", "WARNING": "WARNING       ", "INFO": "INFO          "}
    icon  = icons.get(level, "[?]  ")
    label = labels.get(level, level)
    line  = f"[{timestamp}] {icon} {label} >> {message}"
    print(line)
    ALERTS.append({"level": level, "message": message, "time": timestamp})

# ─────────────────────────────────────────────
# Check if a name matches suspicious signatures
# ─────────────────────────────────────────────
def is_suspicious(name: str) -> bool:
    if not name:
        return False
    name_lower = name.lower()
    return any(sig in name_lower for sig in SUSPICIOUS_NAMES)

# ─────────────────────────────────────────────
# 1. Scan Running Processes
# ─────────────────────────────────────────────
def scan_processes():
    print("\n[*] Scanning running processes...")
    found = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
        try:
            pid     = proc.info['pid']
            name    = proc.info['name'] or ""
            exe     = proc.info['exe']  or ""
            cmdline = " ".join(proc.info['cmdline'] or [])

            if is_suspicious(name) or is_suspicious(exe) or is_suspicious(cmdline):
                alert("CRITICAL",
                      f"Suspicious process: PID={pid} | Name={name} | Path={exe}")
                found += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if found == 0:
        alert("INFO", "No suspicious processes found by name.")
    else:
        alert("WARNING", f"Total suspicious processes found: {found}")

# ─────────────────────────────────────────────
# 2. Detect Keyboard Hooks (Windows only)
# ─────────────────────────────────────────────
def detect_keyboard_hooks_windows():
    print("\n[*] Scanning for keyboard hooks in loaded DLLs (Windows)...")
    found = 0

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid  = proc.info['pid']
            name = proc.info['name'] or "unknown"

            # Check DLLs/maps loaded in this process
            maps = proc.memory_maps()
            for m in maps:
                path_lower = m.path.lower()
                if any(kw in path_lower for kw in ["hook", "keylog", "spy", "inject"]):
                    alert("CRITICAL",
                          f"Suspicious DLL in PID={pid} [{name}]: {m.path}")
                    found += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            continue

    if found == 0:
        alert("INFO", "No suspicious hooked DLLs detected.")

# ─────────────────────────────────────────────
# 3. Scan Windows Registry Startup Entries
# ─────────────────────────────────────────────
def scan_registry_windows():
    print("\n[*] Scanning Windows registry startup keys...")
    try:
        import winreg
    except ImportError:
        alert("WARNING", "winreg not available (not Windows or restricted).")
        return

    startup_keys = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, key_path in startup_keys:
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    value_name, value_data, _ = winreg.EnumValue(key, i)
                    if is_suspicious(value_name) or is_suspicious(str(value_data)):
                        alert("CRITICAL",
                              f"Suspicious startup entry: [{value_name}] -> {value_data}")
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError):
            continue

# ─────────────────────────────────────────────
# 4. Scan Linux /proc + Kernel Modules
# ─────────────────────────────────────────────
def scan_linux_specifics():
    print("\n[*] Checking loaded kernel modules (Linux)...")
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                mod_name = line.split()[0]
                if is_suspicious(mod_name):
                    alert("CRITICAL",
                          f"Suspicious kernel module loaded: {mod_name}")
    except FileNotFoundError:
        alert("WARNING", "/proc/modules not accessible.")

    print("\n[*] Checking common keylogger drop paths (Linux)...")
    suspicious_paths = [
        "/tmp/.hidden", "/var/tmp/.hidden",
        "/root/.cache/.log", "/home/.hidden",
        "/etc/.keylog", "/usr/share/.spy"
    ]
    for path in suspicious_paths:
        if os.path.exists(path):
            alert("WARNING", f"Suspicious hidden path exists: {path}")

# ─────────────────────────────────────────────
# 5. Scan Open Network Connections (data exfil)
# ─────────────────────────────────────────────
def scan_network_connections():
    print("\n[*] Scanning network connections for suspicious activity...")
    found = 0

    # Known malicious / uncommon exfil ports
    suspicious_ports = {1337, 4444, 5555, 6666, 7777, 9999, 31337}

    for conn in psutil.net_connections(kind='inet'):
        try:
            raddr = conn.raddr
            if not raddr:
                continue
            if conn.status == "ESTABLISHED" and raddr.port in suspicious_ports:
                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name()
                except Exception:
                    pname = "unknown"
                alert("WARNING",
                      f"Suspicious outbound connection: PID={conn.pid} [{pname}] "
                      f"-> {raddr.ip}:{raddr.port}")
                found += 1
        except Exception:
            continue

    if found == 0:
        alert("INFO", "No suspicious network connections found.")

# ─────────────────────────────────────────────
# 6. Detect High-Frequency Background Processes
# ─────────────────────────────────────────────
def detect_background_programs():
    print("\n[*] Detecting unknown high-CPU background programs...")
    found = 0

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            cpu = proc.cpu_percent(interval=0.1)
            if cpu > 15.0:
                name = proc.info['name'] or "unknown"
                exe  = proc.info['exe']  or "N/A"
                # Only flag if not a common system process
                common = ["system", "svchost", "explorer", "chrome",
                          "firefox", "python", "code", "idle"]
                if not any(c in name.lower() for c in common):
                    alert("WARNING",
                          f"High-CPU background process: PID={proc.pid} "
                          f"| Name={name} | CPU={cpu:.1f}% | Path={exe}")
                    found += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if found == 0:
        alert("INFO", "No suspicious high-CPU background programs found.")

# ─────────────────────────────────────────────
# Summary Report
# ─────────────────────────────────────────────
def print_summary():
    criticals = [a for a in ALERTS if a["level"] == "CRITICAL"]
    warnings  = [a for a in ALERTS if a["level"] == "WARNING"]

    print("\n" + "═" * 60)
    print("  SCAN SUMMARY")
    print("═" * 60)
    print(f"  Total alerts   : {len(ALERTS)}")
    print(f"  Critical       : {len(criticals)}")
    print(f"  Warnings       : {len(warnings)}")
    print("─" * 60)

    if criticals:
        print("\n  🚨 CRITICAL FINDINGS:")
        for a in criticals:
            print(f"    • {a['message']}")
    else:
        print("\n  ✅ No critical threats detected.")

    if warnings:
        print("\n  ⚠️  WARNINGS:")
        for a in warnings:
            print(f"    • {a['message']}")

    print("\n" + "═" * 60)

# ─────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────
def main():
    print("╔══════════════════════════════════════════════════════╗")
    print("║         KeyloggerDetector v1.0  — Python Edition     ║")
    print("║         github.com/hemanathan115                     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"Platform  : {platform.system()} {platform.release()}")
    print(f"Python    : {sys.version.split()[0]}")
    print(f"Scan time : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 60)

    system = platform.system()

    # Run common checks
    scan_processes()
    scan_network_connections()
    detect_background_programs()

    # Platform-specific checks
    if system == "Windows":
        detect_keyboard_hooks_windows()
        scan_registry_windows()
    elif system == "Linux":
        scan_linux_specifics()
    else:
        alert("INFO", f"Platform '{system}' — skipping OS-specific checks.")

    print_summary()
    print("\nScan complete. Press Enter to exit...")
    input()

if __name__ == "__main__":
    main()
