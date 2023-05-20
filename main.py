import socket 
import random
import time 
import paramiko 
import logging 
import ipaddress 
from rich.console import Console 
from rich.table import Table 
from rich.logging import RichHandler  

console = Console()

def check_port(ip_address, port, timeout=0.5):
    """
    Checks whether or not a port is open for a specified IP address
    """
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_address, port))
        s.close()
        return True
    except:
        return False  

def scan_ips(ip_range, port):
    """
    Scans a range of IP addresses for an open port
    """
    live_ips = []
    for ip in ip_range:
        if check_port(str(ip), port):
            live_ips.append(str(ip))
            console.print(f"IP {ip} is live", style="green")
        else:
            console.print(f"IP {ip} is not live", style="red")

    return live_ips  

def try_ssh(ip_address, username, password, timeout=0.5, banner_timeout=5, max_attempts=3):
    """
    Attempts an SSH connection with a specified username and password for a given IP address.
    Reconnects to the target after 3 failed attempts.
    """
    success = False
    attempts = 0
    while not success and attempts < max_attempts:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip_address, username=username, password=password, timeout=timeout, banner_timeout=banner_timeout)
            success = True
            return True
        except:
            attempts += 1
            console.print(f"Failed to log in to {ip_address} with username: {username} and password: {password}. Attempt {attempts} of {max_attempts}. Retrying...", style="red")
            time.sleep(3)

    if attempts >= max_attempts:
        console.print(f"Reached maximum login attempts for {ip_address}. Reconnecting...", style="yellow")

    return False

def scan_ssh(ip_address):
    """
    Scans an IP address with a range of default usernames and passwords
    to return successful SSH login credentials
    """

    usernames = ['root', 'admin', 'ubuntu', 'kali']
    passwords = ['password', '123456', 'admin', 'toor', 'qwerty', 'kali']
    random.shuffle(passwords)

    remaining_passwords = passwords
    attempts = 3

    while remaining_passwords and attempts > 0:
        current_passwords = remaining_passwords[:attempts]
        remaining_passwords = remaining_passwords[attempts:]

        for user in usernames:
            successful_login = False

            for password in current_passwords:
                if try_ssh(ip_address, user, password):
                    console.print(f"Successfully logged in to {ip_address} with username: {user} and password: {password}", style="green")
                    return

                console.print(f"Failed to log in to {ip_address} with username: {user} and password: {password}", style="red")

                if successful_login:
                    break

        attempts -= 1

    console.print(f"Failed to log in to {ip_address} with the given credentials", style="red")

def print_results_table(credentials):
    """
    Prints a table to the console with successful SSH login credentials
    """
    table = Table(title="SSH Credentials")
    table.add_column("IP Address", justify="center", style="cyan", no_wrap=True)
    table.add_column("Username", justify="center", style="purple")
    table.add_column("Password", justify="center", style="green")

    for ip, credential in credentials.items():
        table.add_row(f"[bold]{ip}[/bold]", credential[0], credential[1])
        console.print(f"Successful login to {ip} with username: {credential[0]} and password: {credential[1]}", style="green")

    console.print(table)

def write_to_file(credentials):
    """
    Writes successful SSH login credentials to a file
    """
    with open("successful_logins.txt", "a") as f:
        for ip, credential in credentials.items():
            f.write(f"{ip}\t{credential[0]}\t{credential[1]}\n")

def main():
    """
    Main function to be run
    """
    while True:
        ip_range = input("Please enter the IP range to be scanned: ")
        try:
            parsed_ip_range = ipaddress.ip_network(ip_range)
            ip_list = list(parsed_ip_range.hosts())
            break
        except ipaddress.AddressValueError:
            console.print("Invalid IP range format. Please try again.", style="bold red")

    port = 22
    live_ips = scan_ips(ip_list, port)

    if len(live_ips) == 0:
        console.print("No live IPs found in range. Exiting.", style="bold red")
        return

    credentials = {}
    for ip in live_ips:
        scan_ssh(ip)
        credentials[ip] = ('', '')

    print_results_table(credentials)
    write_to_file(credentials) 

if __name__ == '__main__':
    main()
