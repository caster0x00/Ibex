# killswitch.py

from ibex.spoof import ModeManager
from ibex.tuning import TuningShell
from ibex.nat64 import IbexNat64Shell
from ibex.dns64 import DNS64Shell
from colorama import Fore, Style

def run_killswitch():
    print(Fore.YELLOW + "\n[*] Ibex Killswitch Mode: Stopping attacks and network recovery" + Style.RESET_ALL)

    # Stop RA Spoofing
    print(Fore.LIGHTBLACK_EX + "---[ RA Spoofing ]---------------------------------" + Style.RESET_ALL)
    try:
        manager = ModeManager()
        manager.stop_all()
        print(Fore.GREEN + "[✓] RA Spoofing disabled (lifetime set to 0)")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to stop RA Spoofing: {e}")

    # Revert system tuning
    print(Fore.LIGHTBLACK_EX + "---[ System Tuning ]-------------------------------" + Style.RESET_ALL)
    try:
        shell = TuningShell()
        shell.do_stop("")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to revert tuning: {e}")

    # Stop NAT64 (Tayga)
    print(Fore.LIGHTBLACK_EX + "---[ NAT64 (Tayga) ]-------------------------------" + Style.RESET_ALL)
    try:
        shell = IbexNat64Shell()
        shell.do_stop("")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to stop NAT64: {e}")

    # Stop DNS64 (BIND9)
    print(Fore.LIGHTBLACK_EX + "---[ DNS64 (named) ]-------------------------------" + Style.RESET_ALL)
    try:
        shell = DNS64Shell()
        shell.do_stop("")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to stop DNS64: {e}")

