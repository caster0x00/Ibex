# sniffing.py

import os
import signal
from datetime import datetime
from colorama import Fore, Style
from scapy.all import sniff, Ether, IPv6, UDP
from scapy.layers.dhcp6 import *
from scapy.layers.inet6 import *
import cmd

DHCP6_TYPES = {
    DHCP6_Solicit: "Solicit",
    DHCP6_Advertise: "Advertise",
    DHCP6_Request: "Request",
    DHCP6_Reply: "Reply",
    DHCP6_Renew: "Renew",
    DHCP6_Rebind: "Rebind",
    DHCP6_RelayForward: "Relay-Forward",
    DHCP6_RelayReply: "Relay-Reply"
}

ICMP6_TYPES = {
    ICMPv6ND_RS: ("RS", Fore.CYAN),
    ICMPv6ND_RA: ("RA", Fore.GREEN),
    ICMPv6ND_NS: ("NS", Fore.BLUE),
    ICMPv6ND_NA: ("NA", Fore.MAGENTA),
    ICMPv6ND_Redirect: ("REDIR", Fore.LIGHTRED_EX),
    ICMPv6MLReport: ("MLD", Fore.LIGHTCYAN_EX),
    ICMPv6MLReport2: ("MLD", Fore.LIGHTCYAN_EX),
    ICMPv6MLDone: ("MLD", Fore.LIGHTCYAN_EX),
    ICMPv6EchoRequest: ("ECHO-REQ", Fore.LIGHTBLACK_EX),
    ICMPv6EchoReply: ("ECHO-REPL", Fore.LIGHTBLACK_EX)
}

_sniffing_state = None


class SniffingState:
    def __init__(self):
        self.interface = None
        self.timer = 0
        self.last_start = None
        self.last_end = None


def handle_packet(pkt):
    eth_src = pkt[Ether].src if Ether in pkt else "?"
    ip6_src = pkt[IPv6].src if IPv6 in pkt else "?"
    ip6_dst = pkt[IPv6].dst if IPv6 in pkt else "?"

    for proto, (short, color) in ICMP6_TYPES.items():
        if proto in pkt:
            if proto is ICMPv6ND_RA:
                prefix = None
                dns = None
                if ICMPv6NDOptPrefixInfo in pkt:
                    prefix = pkt[ICMPv6NDOptPrefixInfo].prefix
                if ICMPv6NDOptRDNSS in pkt:
                    dns = ', '.join(pkt[ICMPv6NDOptRDNSS].dns)
                msg = f"RA from {ip6_src} (MAC {eth_src})"
                if prefix:
                    msg += f" advertises {prefix}/64"
                if dns:
                    msg += f", DNS: {dns}"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return
            elif proto is ICMPv6ND_RS:
                msg = f"RS from {ip6_src} (MAC {eth_src}) → looking for router"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return
            elif proto is ICMPv6ND_NS:
                msg = f"NS: who has {ip6_dst}? asked by {ip6_src} (MAC {eth_src})"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return
            elif proto is ICMPv6ND_NA:
                msg = f"NA: {ip6_src} is at {eth_src}"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return
            elif "MLD" in short:
                msg = f"MLD from {ip6_src} (MAC {eth_src})"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return
            else:
                msg = f"{short} {ip6_src} → {ip6_dst} (MAC {eth_src})"
                print(color + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return

    if UDP in pkt and pkt[UDP].dport == 547:
        for dhcp_type, name in DHCP6_TYPES.items():
            if dhcp_type in pkt:
                short = f"DHCP-{name}"
                msg = f"{short} from {ip6_src} (MAC {eth_src}) → searching for DHCPv6 server"
                print(Fore.YELLOW + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}" + Style.RESET_ALL)
                return


class SniffingShell(cmd.Cmd):
    prompt = "ibex sniffing> "

    def __init__(self):
        super().__init__()
        global _sniffing_state
        if _sniffing_state is None:
            _sniffing_state = SniffingState()
        self.state = _sniffing_state

    def do_set(self, args):
        parts = args.strip().split()
        if len(parts) != 2:
            print(Fore.RED + "Usage: set <interface|timer> <value>")
            return
        key, value = parts
        if key == "interface":
            self.state.interface = value
            print(Fore.GREEN + f"[*] interface set to {value}")
        elif key == "timer":
            try:
                self.state.timer = int(value)
                print(Fore.GREEN + f"[*] timer set to {value}")
            except ValueError:
                print(Fore.RED + "[!] timer must be integer seconds")
        else:
            print(Fore.RED + "Invalid key")

    def do_show(self, arg):
        print(Fore.YELLOW + "\n[*] Sniffing configuration and stats:\n" + Style.RESET_ALL)
        print(f"  interface: {self.state.interface}")
        print(f"  timer: {self.state.timer or '∞'}")
        print(f"  last run: {self.state.last_start} → {self.state.last_end}" if self.state.last_start else "  last run: none")
        print()

    def do_start(self, arg):
        iface = self.state.interface
        timeout = self.state.timer
        if not iface:
            print(Fore.RED + "Set interface first with: set interface <iface>")
            return

        self.state.last_start = datetime.now().strftime('%H:%M:%S')
        print(Fore.LIGHTWHITE_EX + f"[*] Sniffing on {iface} for {timeout or '∞'} seconds...\n")

        prev_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.default_int_handler)

        try:
            sniff(iface=iface, prn=handle_packet, timeout=timeout or None, store=0)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Sniffing interrupted by user")
        finally:
            signal.signal(signal.SIGINT, prev_handler)

        self.state.last_end = datetime.now().strftime('%H:%M:%S')

    def do_clear(self, arg):
        os.system("clear" if os.name == "posix" else "cls")

    def do_exit(self, arg):
        return True

    def emptyline(self):
        pass

    def do_help(self, arg):
        print("\nAvailable sniffing commands:")
        print("  set interface <iface>          Set default interface")
        print("  set timer <seconds>            Set default timer")
        print("  show                           Show current config and last stats")
        print("  start                          Begin sniffing with saved config")
        print("  clear                          Clear the screen")
        print("  exit                           Return to Ibex main shell\n")

    def complete_set(self, text, line, begidx, endidx):
        import netifaces
        parts = line.strip().split()
        if len(parts) == 1:
            return ['interface', 'timer']
        elif len(parts) == 2:
            return [opt for opt in ['interface', 'timer'] if opt.startswith(text)]
        elif len(parts) == 3 and parts[1] == "interface":
            return [i for i in netifaces.interfaces() if i.startswith(text)]
        return []

    def complete_show(self, text, line, begidx, endidx):
        return []

    def complete_start(self, text, line, begidx, endidx):
        return []

    def complete_clear(self, text, line, begidx, endidx):
        return []

    def complete_exit(self, text, line, begidx, endidx):
        return []

    def complete_help(self, text, line, begidx, endidx):
        return []
