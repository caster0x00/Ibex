# tuning.py

import os
import subprocess
import cmd
import json
from colorama import Fore, Style

# Path to sysctl snapshot file
_snapshot_path = "/tmp/ibex_tuning_snapshot.json"
_tuning_state = None

def auto_detect_interface():
    try:
        output = subprocess.check_output("ip -o link show | awk -F': ' '{print $2}'", shell=True).decode().splitlines()
        for iface in output:
            if iface.startswith(("eth", "enp", "wlan")) and iface != "lo":
                return iface
    except:
        return None
    return None

class TuningState:
    def __init__(self):
        self.interface = auto_detect_interface()

class TuningShell(cmd.Cmd):
    prompt = "ibex tuning> "

    def __init__(self):
        super().__init__()
        global _tuning_state
        if _tuning_state is None:
            _tuning_state = TuningState()
        self.state = _tuning_state
        if self.state.interface:
            print(Fore.WHITE + f"[*] Auto-detected interface: {self.state.interface}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] Failed to auto-detect interface, please set manually via 'set interface <iface>'" + Style.RESET_ALL)

    def run_cmd(self, description, command):
        print(Fore.GREEN + f"[+] {description}")
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def do_set(self, args):
        parts = args.strip().split()
        if len(parts) != 2 or parts[0] != "interface":
            print(Fore.RED + "Usage: set interface <iface>")
            return
        iface = parts[1]
        if not os.path.exists(f"/sys/class/net/{iface}"):
            print(Fore.RED + f"[-] Interface '{iface}' does not exist")
            return
        self.state.interface = iface
        print(Fore.GREEN + f"[*] Interface set to {self.state.interface}")

    def do_show(self, args):
        iface = self.state.interface
        if not iface:
            print(Fore.RED + "Set interface first with: set interface <iface>")
            return
        print(Fore.YELLOW + f"\n[*] Current tuning status for interface: {iface}\n")

        def check(desc, cmd):
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            status = result.stdout.strip() or "N/A"
            print(Fore.GREEN + f"✓ {desc:<28}→ {Fore.WHITE}{status}")

        check("IPv6 forwarding", "sysctl -n net.ipv6.conf.all.forwarding")
        check("RA acceptance", "sysctl -n net.ipv6.conf.all.accept_ra")
        check("ICMPv6 redirects", "sysctl -n net.ipv6.conf.all.accept_redirects")
        check("Promiscuous mode", f"ip link show {iface} | grep -q PROMISC && echo ON || echo OFF")
        check("ip6tables FORWARD rule", f"ip6tables -S FORWARD | grep -q '\\-i {iface}' && echo Present || echo Missing")
        check("ip6tables MASQUERADE", f"ip6tables -t nat -S POSTROUTING | grep -q '\\-o {iface}' && echo Present || echo Missing")

        print(Style.RESET_ALL)

    def do_plan(self, args):
        print(Fore.LIGHTYELLOW_EX + "\n[*] Planned tuning actions:\n")
        actions = self.get_actions(enable=True)
        for desc, _ in actions:
            print("  ✓ " + desc)
        print(Style.RESET_ALL)

    def do_start(self, args):
        iface = self.state.interface
        if not iface:
            print(Fore.RED + "Set interface first with: set interface <iface>")
            return
        self.snapshot_sysctl()
        print(Fore.LIGHTWHITE_EX + f"[*] Applying tuning to {iface}...\n")
        actions = self.get_actions(enable=True)
        for desc, cmd in actions:
            self.run_cmd(desc, cmd)
        print(Fore.LIGHTWHITE_EX + "\n[*] Tuning applied\n" + Style.RESET_ALL)

    def do_stop(self, args):
        iface = self.state.interface
        if not iface:
            print(Fore.RED + "Set interface first with: set interface <iface>")
            return
        print(Fore.LIGHTWHITE_EX + f"[*] Reverting tuning for {iface}...\n")
        if os.path.exists(_snapshot_path):
            with open(_snapshot_path) as f:
                original = json.load(f)
            for key, value in original.items():
                self.run_cmd(f"Restore {key}", f"sysctl -w {key}={value}")
            os.remove(_snapshot_path)
            print(Fore.GREEN + f"[+] Snapshot restored and {_snapshot_path} removed")
        else:
            print(Fore.YELLOW + f"[!] No snapshot found at {_snapshot_path}, skipping sysctl restore")
        actions = self.get_actions(enable=False)
        for desc, cmd in actions:
            self.run_cmd(desc, cmd)
        print(Fore.LIGHTWHITE_EX + "[*] Tuning reverted\n" + Style.RESET_ALL)

    def get_actions(self, enable=True):
        iface = self.state.interface
        if enable:
            return [
                ("Enable promiscuous mode", f"ip link set dev {iface} promisc on"),
                ("Disable RA", "sysctl -w net.ipv6.conf.all.accept_ra=0"),
                ("Disable ICMPv6 Redirects", "sysctl -w net.ipv6.conf.all.accept_redirects=0"),
                ("Drop ICMPv6 Redirect IN", "ip6tables -C INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP || ip6tables -A INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP"),
                ("Drop ICMPv6 Redirect OUT", "ip6tables -C OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP || ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP"),
                ("Raise open files limit", "sysctl -w fs.file-max=100000"),
                ("Increase backlog", "sysctl -w net.core.somaxconn=65535"),
                ("Increase packet queue", "sysctl -w net.core.netdev_max_backlog=65536"),
                ("Reduce TCP FIN timeout", "sysctl -w net.ipv4.tcp_fin_timeout=15"),
                ("Enable TCP TIME-WAIT reuse", "sysctl -w net.ipv4.tcp_tw_reuse=1"),
                ("Raise TIME-WAIT buckets", "sysctl -w net.ipv4.tcp_max_tw_buckets=65536"),
                ("Enable window scaling", "sysctl -w net.ipv4.tcp_window_scaling=1"),
                ("Enable IPv4 forwarding", "sysctl -w net.ipv4.ip_forward=1"),
                ("Enable IPv6 forwarding", "sysctl -w net.ipv6.conf.all.forwarding=1"),
                ("Allow FORWARD ip6tables", f"ip6tables -C FORWARD -i {iface} -j ACCEPT || ip6tables -A FORWARD -i {iface} -j ACCEPT"),
                ("Enable NAT MASQUERADE", f"ip6tables -t nat -C POSTROUTING -o {iface} -j MASQUERADE || ip6tables -t nat -A POSTROUTING -o {iface} -j MASQUERADE"),
            ]
        else:
            return [
                ("Disable promiscuous mode", f"ip link set dev {iface} promisc off"),
                ("Remove ICMPv6 redirect DROP IN", "ip6tables -D INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP"),
                ("Remove ICMPv6 redirect DROP OUT", "ip6tables -D OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP"),
                ("Remove FORWARD rule", f"ip6tables -D FORWARD -i {iface} -j ACCEPT"),
                ("Remove MASQUERADE rule", f"ip6tables -t nat -D POSTROUTING -o {iface} -j MASQUERADE"),
            ]

    def snapshot_sysctl(self):
        keys = [
            "net.ipv6.conf.all.forwarding",
            "net.ipv4.ip_forward",
            "net.ipv6.conf.all.accept_ra",
            "net.ipv6.conf.all.accept_redirects",
            "fs.file-max",
            "net.core.somaxconn",
            "net.core.netdev_max_backlog",
            "net.ipv4.tcp_fin_timeout",
            "net.ipv4.tcp_tw_reuse",
            "net.ipv4.tcp_max_tw_buckets",
            "net.ipv4.tcp_window_scaling"
        ]
        snapshot = {}
        for key in keys:
            result = subprocess.run(f"sysctl -n {key}", shell=True, stdout=subprocess.PIPE, text=True)
            snapshot[key] = result.stdout.strip()
        with open(_snapshot_path, "w") as f:
            json.dump(snapshot, f)

    def do_clear(self, args):
        os.system("clear" if os.name == "posix" else "cls")

    def do_exit(self, args):
        return True

    def emptyline(self):
        pass

    def do_help(self, arg):
        print(Fore.YELLOW + "\nAvailable tuning commands:\n" + Style.RESET_ALL)
        print("  set interface <iface>   Set default interface")
        print("  show                    Show current tuning state")
        print("  plan                    Preview tuning actions")
        print("  start                   Apply system tuning")
        print("  stop                    Revert system tuning")
        print("  clear                   Clear the screen")
        print("  exit                    Return to Ibex main shell\n")

    def complete_set(self, text, line, begidx, endidx):
        opts = ["interface"]
        parts = line.strip().split()
        if len(parts) == 1:
            return opts
        elif len(parts) == 2:
            return [o for o in opts if o.startswith(text)]
        return []

    def complete_show(self, *args): return []
    def complete_start(self, *args): return []
    def complete_stop(self, *args): return []
    def complete_plan(self, *args): return []
    def complete_clear(self, *args): return []
    def complete_exit(self, *args): return []
    def complete_help(self, *args): return []