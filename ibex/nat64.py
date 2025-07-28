# nat64.py

import os
import subprocess
import cmd
from colorama import Fore, Style

_nat64_state = None

def auto_detect_interface():
    try:
        output = subprocess.check_output(
            "ip -o link show | awk -F': ' '{print $2}'", shell=True
        ).decode().splitlines()
        for iface in output:
            if iface.startswith(("eth", "enp", "ens", "eno", "enx", "wlan", "br", "tap", "tun")) and iface != "lo":
                return iface
    except Exception:
        return None
    return None

class Nat64State:
    def __init__(self):
        self.interface = auto_detect_interface()
        self.prefix = '2001:db8:1:FFFF::/96'
        self.ipv6_host = '2001:db8:1::2'
        self.ipv6_nat64 = '2001:db8:1::3'
        self.ipv4_nat64 = '192.168.255.1'
        self.dynamic_pool = '192.168.255.0/24'
        self.tayga_conf = '/etc/tayga.conf'
        self.ipv6_assigned = False

        if self.interface:
            print(Fore.WHITE + f"[*] Interface auto-detected: {self.interface}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "[!] Failed to auto-detect interface, please set manually via 'set interface <iface>'" + Style.RESET_ALL)

class IbexNat64Shell(cmd.Cmd):
    prompt = 'ibex nat64> '

    def __init__(self):
        super().__init__()
        global _nat64_state
        if _nat64_state is None:
            _nat64_state = Nat64State()
        self.state = _nat64_state

    def run(self, cmd):
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def check(self, cmd):
        return subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    def do_set(self, args):
        parts = args.strip().split()
        if len(parts) != 2:
            print(Fore.RED + "[!] Usage: set <interface|prefix|ipv6_host|ipv6_nat64|ipv4_nat64|dynamic_pool> <value>")
            return
        key, value = parts
        if not hasattr(self.state, key):
            print(Fore.RED + "[!] Invalid setting")
            return
        setattr(self.state, key, value)
        print(Fore.GREEN + f"[*] {key} set to {value}")

    def do_show(self, args):
        print(Fore.YELLOW + "\n[*] Current NAT64 Configuration:\n" + Style.RESET_ALL)
        for key in vars(self.state):
            print(f"  ✓ {key:<15} → {getattr(self.state, key)}")
        print()

    def do_plan(self, args):
        print(Fore.LIGHTYELLOW_EX + "\n[*] Planned NAT64 actions:\n")
        steps = [
            "Write Tayga config",
            "Create nat64 tunnel interface",
            "Assign IPv6/IPv4 addresses",
            "Add IPv6 and IPv4 routes",
            "Add iptables rules",
            "Launch Tayga",
        ]
        for step in steps:
            print(f"  ✓ {step}")
        print(Style.RESET_ALL)

    def build_config(self):
        with open(self.state.tayga_conf, 'w') as f:
            f.write(f"""tun-device nat64
ipv4-addr {self.state.ipv4_nat64}
prefix {self.state.prefix}
dynamic-pool {self.state.dynamic_pool}
""")

    def do_start(self, args):
        if not self.state.interface:
            print(Fore.RED + "[!] Set interface first: set interface <iface>")
            return

        iface = self.state.interface
        self.build_config()
        self.run("mkdir -p /var/spool/tayga")

        self.run("tayga --mktun")
        self.run("ip link set nat64 up")
        self.run(f"ip addr add {self.state.ipv6_host}/64 dev {iface}")
        self.state.ipv6_assigned = True

        self.run(f"ip addr add {self.state.ipv6_nat64} dev nat64")
        self.run(f"ip addr add {self.state.ipv4_nat64} dev nat64")
        self.run(f"ip route add {self.state.dynamic_pool} dev nat64")
        self.run(f"ip -6 route add {self.state.prefix} dev nat64")

        self.run(f"iptables -t nat -C POSTROUTING -o {iface} -j MASQUERADE || iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        self.run(f"iptables -C FORWARD -i nat64 -o {iface} -j ACCEPT || iptables -A FORWARD -i nat64 -o {iface} -j ACCEPT")
        self.run(f"iptables -C FORWARD -i {iface} -o nat64 -m state --state RELATED,ESTABLISHED -j ACCEPT || iptables -A FORWARD -i {iface} -o nat64 -m state --state RELATED,ESTABLISHED -j ACCEPT")

        subprocess.Popen(["tayga"])
        print(Fore.LIGHTYELLOW_EX + "\n[*] Launching test ping via NAT64...\n")
        test_target = f"{self.state.prefix.split('/')[0]}8.8.8.8"
        res1 = subprocess.run(["ping6", "-c", "1", test_target], stdout=subprocess.DEVNULL)
        if res1.returncode == 0:
            print(Fore.GREEN + f"[*] NAT64 working")
        else:
            print(Fore.RED + f"[!] NAT64 failed: ping to {test_target} unsuccessful\n")
            print(Fore.YELLOW + "\n[*] NAT64 infrastructure started.\n")

    def do_stop(self, args):
        print(Fore.RED + "[*] Stopping NAT64 infrastructure..." + Style.RESET_ALL)

        iface = self.state.interface or "eth0"
        pid = subprocess.getoutput("pidof tayga")

        if pid:
            print(Fore.CYAN + f"[*] Found tayga process: PID {pid}")
        else:
            print(Fore.YELLOW + "[!] No tayga process found")

        print(Fore.LIGHTWHITE_EX + "[*] Removing interface addresses:")
        print(f"    - {self.state.ipv6_host}/64 from {iface}")
        print(f"    - {self.state.ipv6_nat64} from nat64")
        print(f"    - {self.state.ipv4_nat64} from nat64")
        self.run(f"ip addr del {self.state.ipv6_host}/64 dev {iface}")
        self.run(f"ip addr del {self.state.ipv6_nat64} dev nat64")
        self.run(f"ip addr del {self.state.ipv4_nat64} dev nat64")

        print(Fore.LIGHTWHITE_EX + "[*] Deleting routes:")
        print(f"    - IPv6: {self.state.prefix}")
        print(f"    - IPv4: {self.state.dynamic_pool}")
        self.run(f"ip route del {self.state.dynamic_pool} dev nat64")
        self.run(f"ip -6 route del {self.state.prefix} dev nat64")

        print(Fore.LIGHTWHITE_EX + "[*] Removing iptables rules:")
        print(f"    - MASQUERADE for {iface}")
        print("    - FORWARD nat64 → iface")
        print("    - FORWARD iface → nat64 (RELATED,ESTABLISHED)")
        self.run(f"iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE")
        self.run(f"iptables -D FORWARD -i nat64 -o {iface} -j ACCEPT")
        self.run(f"iptables -D FORWARD -i {iface} -o nat64 -m state --state RELATED,ESTABLISHED -j ACCEPT")

        print(Fore.LIGHTWHITE_EX + "[*] Bringing down and deleting interface nat64")
        self.run("ip link set nat64 down")
        self.run("ip link delete nat64")

        print(Fore.LIGHTWHITE_EX + "[*] Killing tayga process...")
        self.run("pkill -9 tayga")

        print(Fore.GREEN + "[*] NAT64 stopped." + Style.RESET_ALL)

    def do_status(self, args):
        iface = self.state.interface or "N/A"
        print(Fore.LIGHTCYAN_EX + "\n[*] Current NAT64 status:\n")

        def flag(label, ok):
            mark = "✓" if ok else "✗"
            color = Fore.GREEN if ok else Fore.RED
            print(f"{color}  {mark} {label}")

        flag("nat64 interface present", self.check("ip link show nat64"))
        flag("tayga process running", self.check("pidof tayga"))
        flag(f"{iface}: IPv6 host assigned", self.check(f"ip -6 addr show dev {iface} | grep {self.state.ipv6_host}"))
        flag("nat64 has IPv6 addr", self.check(f"ip -6 addr show dev nat64 | grep {self.state.ipv6_nat64}"))
        flag("nat64 has IPv4 addr", self.check(f"ip addr show dev nat64 | grep {self.state.ipv4_nat64}"))
        flag("IPv6 route present", self.check("ip -6 route show dev nat64 | grep -q '/96'"))
        flag("IPv4 route present", self.check(f"ip route | grep {self.state.dynamic_pool}"))
        flag("iptables MASQUERADE", self.check(f"iptables -t nat -C POSTROUTING -o {iface} -j MASQUERADE"))
        flag("iptables FORWARD nat64→iface", self.check(f"iptables -C FORWARD -i nat64 -o {iface} -j ACCEPT"))
        flag("iptables FORWARD iface→nat64", self.check(f"iptables -C FORWARD -i {iface} -o nat64 -m state --state RELATED,ESTABLISHED -j ACCEPT"))

        print(Style.RESET_ALL)

    def do_clear(self, args):
        os.system("clear" if os.name == "posix" else "cls")

    def do_exit(self, args):
        return True

    def emptyline(self): pass

    def do_help(self, arg):
        print(Fore.YELLOW + "\nAvailable NAT64 commands:\n" + Style.RESET_ALL)
        print("  set <key> <value>       Set configuration option")
        print("  show                    Show current NAT64 config")
        print("  plan                    Preview NAT64 setup steps")
        print("  start                   Start NAT64 (Tayga) service")
        print("  stop                    Stop NAT64 and clean up")
        print("  status                  Show NAT64 operational state")
        print("  clear                   Clear the screen")
        print("  exit                    Return to Ibex main shell\n")

    def complete_set(self, text, line, begidx, endidx):
        opts = [
            'interface',
            'prefix',
            'ipv6_host',
            'ipv6_nat64',
            'ipv4_nat64',
            'dynamic_pool'
        ]
        parts = line.strip().split()
        if len(parts) == 1:
            return opts
        elif len(parts) == 2:
            return [o for o in opts if o.startswith(text)]
        return []

    def complete_show(self, *args): return []
    def complete_plan(self, *args): return []
    def complete_start(self, *args): return []
    def complete_stop(self, *args): return []
    def complete_status(self, *args): return []
    def complete_clear(self, *args): return []
    def complete_exit(self, *args): return []
    def complete_help(self, *args): return []
