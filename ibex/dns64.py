import os
import subprocess
import cmd
import shutil
from colorama import Fore, Style
from datetime import datetime

# Paths for DNS64 runtime, logs, and temp data
BASE_DIR = "/var/lib/ibex/dns64"
LOG_DIR = "/var/log/ibex"
RUN_DIR = "/run/ibex"
RESOLV_PATH = "/etc/resolv.conf"

_dns64_state = None

def ensure_directories():
    for path in [BASE_DIR, LOG_DIR, RUN_DIR]:
        os.makedirs(path, exist_ok=True)

def cleanup_directories():
    for path in [BASE_DIR, RUN_DIR]:
        if os.path.exists(path):
            shutil.rmtree(path)

class DNS64State:
    def __init__(self):
        ensure_directories()
        self.prefix = "2001:db8:1:FFFF::/96"
        self.forwarder = None
        self.log_file = self.generate_log_filename()
        self.named_conf = os.path.join(BASE_DIR, "named.conf")
        self.named_process = None

    def generate_log_filename(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(LOG_DIR, f"captured_hosts_{ts}.log")

class DNS64Shell(cmd.Cmd):
    prompt = 'ibex dns64> '

    def __init__(self):
        super().__init__()
        global _dns64_state
        if _dns64_state is None:
            _dns64_state = DNS64State()
        self.state = _dns64_state

    def emptyline(self): pass

    def do_set(self, args):
        parts = args.strip().split()
        if len(parts) != 2:
            print(Fore.RED + "[!] Usage: set <prefix|forwarder> <value>")
            return

        key, value = parts
        if key == "prefix":
            self.state.prefix = value
        elif key == "forwarder":
            self.state.forwarder = value
        else:
            print(Fore.RED + "[!] Invalid setting")
            return

        print(Fore.GREEN + f"[*] {key} set to {value}")

    def do_show(self, args):
        print(Fore.YELLOW + "\n[*] Current DNS64 Configuration:\n" + Style.RESET_ALL)
        print(f"  prefix:      {self.state.prefix}")
        print(f"  forwarder:   {self.state.forwarder}")
        print(f"  log file:    {self.state.log_file}")
        print()

    def generate_conf(self):
        forwarder_block = f"""
    forwarders {{
        {self.state.forwarder};
    }};""" if self.state.forwarder else ""

        with open(self.state.named_conf, "w") as f:
            f.write(f"""logging {{
    channel intercepted_log {{
        file "{self.state.log_file}";
        severity info;
        print-time yes;
    }};
    category queries {{
        intercepted_log;
    }};
}};

options {{
    directory "/var/cache/bind";

    dns64 {self.state.prefix} {{
        clients {{ any; }};
        mapped {{ any; }};
        exclude {{ ::ffff:0.0.0.0/96; }};
    }};{forwarder_block}

    listen-on-v6 {{ any; }};
    allow-query {{ any; }};
    recursion yes;
    querylog yes;
    pid-file "{os.path.join(RUN_DIR, "named.pid")}";
}};
""")
        print(Fore.GREEN + f"[*] BIND9 config written to {self.state.named_conf}")

    def patch_resolv(self):
        if not os.path.exists(RESOLV_PATH):
            return

        with open(RESOLV_PATH, "r") as f:
            lines = f.readlines()

        if any("nameserver ::1" in line for line in lines):
            print(Fore.YELLOW + "[*] nameserver ::1 already present in resolv.conf")
            return

        with open(RESOLV_PATH, "a") as f:
            f.write("nameserver ::1\n")

        print(Fore.GREEN + "[*] nameserver ::1 added to /etc/resolv.conf")

    def restore_resolv(self):
        if not os.path.exists(RESOLV_PATH):
            return

        with open(RESOLV_PATH, "r") as f:
            lines = f.readlines()

        new_lines = [line for line in lines if "nameserver ::1" not in line]

        with open(RESOLV_PATH, "w") as f:
            f.writelines(new_lines)

        print(Fore.GREEN + "[*] nameserver ::1 removed from /etc/resolv.conf")

    def do_start(self, args):
        if self.state.named_process and self.state.named_process.poll() is None:
            print(Fore.YELLOW + f"[!] named already running (PID {self.state.named_process.pid})")
            return

        if not self.state.forwarder:
            print(Fore.YELLOW + "[!] Forwarder is not set. Continuing without upstream DNS...")

        ensure_directories()
        self.generate_conf()
        self.patch_resolv()

        print(Fore.GREEN + "[*] Starting BIND9 with DNS64 support...")
        self.state.named_process = subprocess.Popen(
            ["named", "-c", self.state.named_conf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(Fore.GREEN + f"[+] named started with PID {self.state.named_process.pid}")

    def do_reload(self, args):
        print(Fore.CYAN + "[*] Reloading DNS64 configuration...")

        if self.state.named_process and self.state.named_process.poll() is None:
            self.state.named_process.terminate()
            try:
                self.state.named_process.wait(timeout=3)
                print(Fore.GREEN + "[+] named terminated.")
            except subprocess.TimeoutExpired:
                self.state.named_process.kill()
                print(Fore.YELLOW + "[!] named killed after timeout.")
        else:
            pid_file = os.path.join(RUN_DIR, "named.pid")
            if os.path.exists(pid_file):
                try:
                    with open(pid_file) as f:
                        pid = int(f.read().strip())
                    os.kill(pid, 15)
                    print(Fore.YELLOW + f"[!] Terminated named (PID {pid}) from PID file")
                except Exception as e:
                    print(Fore.RED + f"[!] Failed to kill named: {e}")

        ensure_directories()
        self.generate_conf()
        self.patch_resolv()

        print(Fore.GREEN + "[*] Starting BIND9 with DNS64 support...")
        self.state.named_process = subprocess.Popen(
            ["named", "-c", self.state.named_conf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(Fore.GREEN + f"[+] named started with PID {self.state.named_process.pid}")

    def do_stop(self, args):
        print(Fore.RED + "[*] Stopping DNS64 service (named)..." + Style.RESET_ALL)

        pid = None
        pid_file = os.path.join(RUN_DIR, "named.pid")
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                print(Fore.CYAN + f"[*] Found named process: PID {pid}")
            except:
                print(Fore.YELLOW + "[!] Failed to read PID from file")

        if self.state.named_process and self.state.named_process.poll() is None:
            self.state.named_process.terminate()
            try:
                self.state.named_process.wait(timeout=3)
                print(Fore.GREEN + "[✓] named terminated (tracked process).")
            except subprocess.TimeoutExpired:
                self.state.named_process.kill()
                print(Fore.YELLOW + "[!] named killed after timeout (tracked process).")
        elif pid:
            try:
                os.kill(pid, 15)
                print(Fore.GREEN + f"[✓] named terminated (PID {pid} from file).")
            except Exception as e:
                print(Fore.RED + f"[!] Failed to kill named (PID {pid}): {e}")
        else:
            print(Fore.YELLOW + "[!] No running named process found.")

        if os.path.exists(self.state.named_conf):
            print(Fore.LIGHTWHITE_EX + f"[*] Deleting config: {self.state.named_conf}")
            try:
                os.remove(self.state.named_conf)
            except Exception as e:
                print(Fore.RED + f"[!] Failed to delete config: {e}")

        self.restore_resolv()
        cleanup_directories()
        print(Fore.CYAN + "[*] Cleaned up DNS64 state (resolv.conf, temp dirs)")

        print(Fore.GREEN + "[✓] DNS64 stopped." + Style.RESET_ALL)
        self.state.named_process = None

    def do_clear(self, args):
        os.system("clear" if os.name == "posix" else "cls")

    def do_exit(self, args):
        return True

    def do_quit(self, args):
        return True

    def do_help(self, arg):
        print(Fore.YELLOW + "\nAvailable DNS64 commands:\n" + Style.RESET_ALL)
        print("  set <key> <value>       Set configuration option (prefix, forwarder)")
        print("  show                    Show current DNS64 config")
        print("  start                   Start DNS64 (bind9/named) service")
        print("  stop                    Stop DNS64 and clean up")
        print("  reload                  Reload config and restart BIND9")
        print("  clear                   Clear the screen")
        print("  exit / quit             Return to Ibex main shell\n")

    def complete_set(self, text, line, begidx, endidx):
        opts = ['prefix', 'forwarder']
        parts = line.strip().split()

        if len(parts) == 1:
            return opts
        elif len(parts) == 2:
            return [o for o in opts if o.startswith(text)]
        return []

    def complete_show(self, *args): return []
    def complete_start(self, *args): return []
    def complete_stop(self, *args): return []
    def complete_reload(self, *args): return []
    def complete_clear(self, *args): return []
    def complete_exit(self, *args): return []
    def complete_quit(self, *args): return []
    def complete_help(self, *args): return []


if __name__ == "__main__":
    DNS64Shell().cmdloop()