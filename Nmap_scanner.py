import nmap

def scan_vulnerabilities(ip_address):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments='-sV -F -v')  # Fast scan with default options
        for host in nm.all_hosts():
            print(f"Scanning host: {host}")
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                for port in ports:
                    service = nm[host][protocol][port]
                    print(f"Port {port}/{protocol}: {service['name']} ({service['product']})")
    except Exception as e:
        print(f"Error during scanning: {e}")

if __name__ == "__main__":
    target_ip = input("What is the IP you would like you scan? ")
    scan_vulnerabilities(target_ip)