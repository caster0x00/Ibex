# watcher.py

import os
import psutil
import netifaces
import platform
import cmd
from colorama import Fore, Style

class WatcherShell(cmd.Cmd):
    prompt = 'ibex watcher> '

    def _iface_exists(self, iface):
        return iface in netifaces.interfaces()

    def _print_header(self, text, color=Fore.YELLOW):
        print(color + text + Style.RESET_ALL)

    def emptyline(self):
        pass

    def do_list(self, arg):
        self._print_header("[*] Available interfaces:\n")
        for iface, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(iface)
            mac = next((s.address for s in addrs if s.family == psutil.AF_LINK), 'N/A')
            status = "UP" if stats and stats.isup else "DOWN"
            mtu = stats.mtu if stats else "?"
            print(Fore.CYAN + f"{iface:<10}" + Fore.GREEN + f"{status:<8}" +
                  Fore.YELLOW + f"{mac:<20}" + Fore.MAGENTA + f"<MTU: {mtu}>" + Style.RESET_ALL)
        print()

    def do_show(self, iface):
        iface = iface.strip()
        if not iface:
            self._print_header("Usage: show <interface>", Fore.RED)
            return
        if not self._iface_exists(iface):
            self._print_header(f"[!] Interface {iface} not found", Fore.RED)
            return
        self._print_header(f"[*] Interface: {iface}")
        addrs = netifaces.ifaddresses(iface)
        stats = psutil.net_if_stats().get(iface)
        mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
        print(f"    MAC:       {mac}")
        if stats:
            print(f"    Status:    {'UP' if stats.isup else 'DOWN'}")
            print(f"    MTU:       {stats.mtu}")
        for af in (netifaces.AF_INET, netifaces.AF_INET6):
            if af in addrs:
                for entry in addrs[af]:
                    ip = entry.get('addr').split('%')[0]
                    label = "IPv4" if af == netifaces.AF_INET else "IPv6"
                    print(f"    {label:<8} {ip}")
        print()

    def do_routes(self, arg):
        iface = arg.strip()
        if iface and not self._iface_exists(iface):
            self._print_header(f"[!] Interface {iface} not found", Fore.RED)
            return
        scope = f" dev {iface}" if iface else ""
        header = f"[*] Routing table for {iface}" if iface else "[*] Routing table"
        self._print_header(f"{header}:\n")
        if platform.system() == "Linux":
            print(Fore.CYAN + "[+] IPv4:" + Style.RESET_ALL)
            os.system(f"ip -4 route show{scope}")
            print()
            print(Fore.CYAN + "[+] IPv6:" + Style.RESET_ALL)
            os.system(f"ip -6 route show{scope}")
        else:
            print("Route display not supported on this platform.")
        print()

    def do_full(self, arg):
        self.do_list(arg)
        self.do_routes("")

    def do_clear(self, arg):
        os.system("clear" if os.name == "posix" else "cls")

    def do_exit(self, arg):
        return True

    def do_help(self, arg):
        self._print_header("\nAvailable watching commands:\n")
        print("  list                      Show all interfaces (summary)")
        print("  show <iface>              Interface info (no routes)")
        print("  routes [iface]            Routing table (global or per interface)")
        print("  full                      Summary + global routes")
        print("  clear                     Clear the screen")
        print("  exit                      Return to Ibex main shell\n")

    def complete_show(self, text, line, begidx, endidx):
        return [i for i in netifaces.interfaces() if i.startswith(text)]

    def complete_routes(self, text, line, begidx, endidx):
        return [i for i in netifaces.interfaces() if i.startswith(text)]

    def complete_list(self, *args): return []
    def complete_full(self, *args): return []
    def complete_clear(self, *args): return []
    def complete_exit(self, *args): return []
    def complete_help(self, *args): return []