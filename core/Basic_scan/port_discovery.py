import socket
import concurrent.futures
import logging
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_service_name(port, protocol='tcp'):
    try:
        service_name = socket.getservbyport(port, protocol)
        return service_name
    except OSError:
        return 'Unknown service'

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)  # Adjust timeout as needed
            result = s.connect_ex((ip, port))
            if result == 0:
                service_name = get_service_name(port)
                return (ip, port, service_name)
    except Exception as e:
        logger.error(f"Error scanning port {port} on {ip}: {e}")
        return None


def scan_ips(ip_range, start_port, end_port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {
            executor.submit(scan_port, str(ip), port): (str(ip), port)
            for ip in ip_range
            for port in range(start_port, end_port + 1)
        }
        for future in concurrent.futures.as_completed(future_to_port):
            ip, port = future_to_port[future]
            result = future.result()
            if result:
                open_ports.append(result)
                logger.info(f"Open port found: {result}")
    return open_ports

def validate_port_range(start_port, end_port):
    if start_port > end_port or start_port < 0 or start_port > 65535 or end_port < 0 or end_port > 65535:
        raise ValueError("Invalid port range. Port numbers must be between 0 and 65535, and start_port must be less than or equal to end_port.")

def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range)
    except ValueError:
        raise ValueError("Invalid IP address or range.")

def get_ip_range():
    choice = input("Enter '1' to scan a specific IP address or '2' for an IP range (CIDR): ")
    if choice == '1':
        ip_address = input("Enter the specific IP address: ")
        return [ip_address]
    elif choice == '2':
        ip_range = input("Enter IP address range (CIDR notation): ")
        validate_ip_range(ip_range)
        return list(ipaddress.ip_network(ip_range).hosts())
    else:
        raise ValueError("Invalid choice. Please enter '1' or '2'.")

if __name__ == "__main__":
    try:
        ip_range = get_ip_range()

        start_port = int(input("Enter starting port number: "))
        end_port = int(input("Enter ending port number: "))
        validate_port_range(start_port, end_port)

        open_ports = scan_ips(ip_range, start_port, end_port)

        if open_ports:
            print("Open ports with services:")
            print("IP Address\tPort\tService")
            print("-----------------------------------------")
            for ip, port, service in open_ports:
                print(f"{ip}\t\t{port}\t{service}")
        else:
            print("No open ports found.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
