# ibexdeps.py

import subprocess
from colorama import Fore, Style

APT_PACKAGES = [
    "tayga",
    "bind9",
    "iproute2",
    "iptables",
    "net-tools",
    "python3-colorama",
    "python3-netifaces",
    "python3-psutil",
    "python3-scapy"
]

def check_apt(pkg):
    return subprocess.call(
        ["dpkg", "-s", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0

def install_apt(pkg):
    subprocess.run(
        ["apt", "install", "-y", pkg],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def check_and_install_all():
    print(Fore.CYAN + "\n[*] Checking dependencies..." + Style.RESET_ALL)
    for pkg in APT_PACKAGES:
        if check_apt(pkg):
            print(Fore.GREEN + f"[✓] {pkg}")
        else:
            print(Fore.YELLOW + f"[✗] Installing {pkg}..." + Style.RESET_ALL)
            install_apt(pkg)
            if check_apt(pkg):
                print(Fore.GREEN + f"[+] Installed {pkg}")
            else:
                print(Fore.RED + f"[!] Failed to install {pkg}")

    print(Fore.CYAN + "\n[*] Dependency check complete.\n" + Style.RESET_ALL)