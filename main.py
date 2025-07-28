#!/usr/bin/env python3

import os
import sys
from colorama import Fore, Style, init
from cmd import Cmd
import signal
from ibex.sniffing import SniffingShell
from ibex.tuning import TuningShell
from ibex.watcher import WatcherShell
from ibex.spoof import SpoofingShell
from ibex.nat64 import IbexNat64Shell
from ibex.dns64 import DNS64Shell
from ibex.killswitch import run_killswitch
import ibex.ibexdeps as ibexdeps

# Colorama
init(autoreset=True)

def disable_sigint():
    def handler(sig, frame):
        print(Fore.RED + "\n[!] CTRL+C is disabled. This is necessary for safe operation with Ibex so that the attack can be stopped and restored." + Style.RESET_ALL)
        print(Fore.YELLOW + "[*] Please use 'exit', stop', or 'killswitch' to terminate operations safely.")
        print(Fore.MAGENTA + "[*] Ensure all active attacks are stopped manually to avoid detection or network instability." + Style.RESET_ALL)
    signal.signal(signal.SIGINT, handler)

def banner():
    banner_text = r"""
  _____ _               
 |_   _| |              
   | | | |__   _____  __
   | | | '_ \ / _ \ \/ /
  _| |_| |_) |  __/>  < 
 |_____|_.__/ \___/_/\_\
"""
    banner_text = "    " + banner_text.replace("\n", "\n    ")
    print(banner_text)
    print("    " + Fore.YELLOW + "Ibex: " + Style.RESET_ALL + "Pwning IPv6 Networks")
    print("    " + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Magama Bazarov, <magamabazarov@mailbox.org>")
    print("    " + Fore.YELLOW + "Alias: " + Style.RESET_ALL + "Caster")
    print("    " + Fore.YELLOW + "Version: " + Style.RESET_ALL + "1.0")
    print("    " + Fore.YELLOW + "Documentation & Usage: " + Style.RESET_ALL + "https://github.com/casterbyte/Ibex\n")
    print("    " + Fore.MAGENTA + "❝The snake which cannot cast its skin has to die❞")
    print("    " + Fore.MAGENTA + "— Friedrich Nietzsche, 1883\n" + Style.RESET_ALL)


class IbexShell(Cmd):
    prompt = "ibex> "

    def do_banner(self, arg): banner()
    def do_clear(self, arg): os.system("clear")
    def do_sniffing(self, arg): SniffingShell().cmdloop()
    def do_tuning(self, arg): TuningShell().cmdloop()
    def do_watcher(self, arg): WatcherShell().cmdloop()
    def do_spoofing(self, arg): SpoofingShell().cmdloop()
    def do_nat64(self, arg): IbexNat64Shell().cmdloop()
    def do_dns64(self, arg): DNS64Shell().cmdloop()
    def do_killswitch(self, arg): run_killswitch()
    def do_exit(self, arg): return True

    def do_about(self, arg):
        print("Ibex by Magama Bazarov aka Caster")
        print("GitHub: https://github.com/casterbyte/Ibex")
        print("Version: 1.0")

    def do_deps(self, arg):
        ibexdeps.check_and_install_all()

    def do_help(self, arg):
        if arg == "":
            print()
            print(Fore.CYAN + "Available commands:" + Style.RESET_ALL)
            print("  watcher     " + "Analysis of interfaces, addresses, and routes")
            print("  sniffing    " + "Traffic analysis for information gathering")
            print("  tuning      " + "Preparing the system for MITM")
            print("  spoofing    " + "MITM Attack Module")
            print("  nat64       " + "Configuring NAT64")
            print("  dns64       " + "Configuring DNS64")
            print("  killswitch  " + "Emergency shutdown for network recovery")
            print("  deps        " + "Install/check all system & Python dependencies")
            print("  banner      " + "Show banner again")
            print("  about       " + "Information about project")
            print("  clear       " + "Clear the screen")
            print("  exit        " + "Exit Ibex")
        else:
            super().do_help(arg)

    def emptyline(self): pass


def main():
    if os.geteuid() != 0:
        print(Fore.RED + "[!] Ibex must be run as root" + Style.RESET_ALL)
        sys.exit(1)

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in ("--version", "-v"):
            print("Ibex v1.0")
            sys.exit(0)
        elif arg in ("--help", "-h"):
            print("Usage:\n  Run without arguments to enter interactive shell.\n  --version / -v    Show version\n  --help    / -h    Show this help message")
            sys.exit(0)
        else:
            print(Fore.RED + f"[!] Unknown argument: {arg}" + Style.RESET_ALL)
            sys.exit(1)

    disable_sigint()
    banner()
    IbexShell().cmdloop()

if __name__ == "__main__":
    main()