
# @authors: Fionn Finane
# This code is an information gathering tool that provides various functionalities such as DNS reconnaissance, Shodan hacking, and network reconnaissance.
from shodan import Shodan
# The Shodan module is imported to allow the tool to interact with the Shodan API for performing reconnaissance tasks related to internet-connected devices and services.
import json
# This code is an information gathering tool that provides various functionalities such as DNS reconnaissance, Shodan hacking, and network reconnaissance.
# The tool also includes a function to resolve all IP addresses for a given target, categorizing them as public or private.    
# The main loop presents a menu to the user and executes the corresponding actions based on the user's choice.
import subprocess
# The subprocess module is used to execute system commands and capture their output.
# This allows the tool to perform various reconnaissance tasks by running commands like NSLOOKUP, DIG, and WHOIS, depending on the user's operating system.
# It utilizes the platform module to identify the operating system and its version, allowing it to tailor its commands and outputs accordingly.
import platform
# The socket module is used for network-related operations, such as resolving hostnames to IP addresses.
import socket
# The ipaddress module is used to handle and manipulate IP addresses.
# It allows the tool to categorize IP addresses as public or private and to determine their version (IPv4 or IPv6).
import ipaddress
# To identify the operating system and its version, we utilize the platform module.
# We store the platform information in the variable 'Your_OS' and the detailed system information in 'System_version'.    
# This allows us to tailor our commands and outputs based on the user's operating system.
Your_OS = platform.platform(terse=True)
# The 'platform.uname()' function provides a tuple containing various details about the system, such as the system name, node name, release, version, machine, and processor.   
# We store this information in the variable 'System_version' for later use in our program.
System_version = platform.uname()
# We initialize a variable 'iterate' to keep track of the number of iterations in our main loop.
# This variable is used to control the flow of the program and determine when to exit the loop based on user input.
iterate = 0
# This allows us to interact with the Shodan API and perform various reconnaissance tasks related to internet-connected devices and services.
api = Shodan("FT3HP85YXqbja1NRPsDYol0orWpua313")  # Replace with your actual Shodan API key
# The 'resolve_all_ips' function takes a target (which can be a hostname or an IP address) as input and attempts to resolve all associated IP addresses, categorizing them as public or private and as IPv4 or IPv6.
# It returns a dictionary containing the resolved IP addresses and the first IP address found, which can be used for further reconnaissance tasks.
def resolve_all_ips(target):
    public_ipv4 = []
    private_ipv4 = []
    public_ipv6 = []
    private_ipv6 = []

    # Helper to add unique IPs to the correct list
    def add_unique(lst, value):
        if value not in lst:
            lst.append(value)

    # CASE 1: Input is already an IP
    try:
        # Attempt to parse the target as an IP address
        ip = ipaddress.ip_address(target)

        if ip.version == 4:
            add_unique(public_ipv4 if ip.is_global else private_ipv4, str(ip))
        else:
            add_unique(public_ipv6 if ip.is_global else private_ipv6, str(ip))

    except ValueError:
        # CASE 2: Hostname

        # Resolve IPv4 addresses
        try:
            for result in socket.getaddrinfo(target, None, socket.AF_INET):
                ip = ipaddress.ip_address(result[4][0])
                add_unique(public_ipv4 if ip.is_global else private_ipv4, str(ip))
        except socket.gaierror:
            pass  # No IPv4 records (not fatal)

        # Resolve IPv6 addresses
        try:
            for result in socket.getaddrinfo(target, None, socket.AF_INET6):
                ip = ipaddress.ip_address(result[4][0])
                add_unique(public_ipv6 if ip.is_global else private_ipv6, str(ip))
        except socket.gaierror:
            pass  # No IPv6 records (very common)

    # Only report failure if NOTHING resolved
    if not (public_ipv4 or public_ipv6 or private_ipv4 or private_ipv6):
        print("[-] Failed to resolve target.")

    # ---------- Helpers ----------
    def stringify(values):
        return values[0] if values else ""

    def first_ip(*groups):
        for group in groups:
            if group:
                return group[0]
        return ""

    # ---------- Return ----------
    return {
        "public_ipv4": stringify(public_ipv4),
        "private_ipv4": stringify(private_ipv4),
        "public_ipv6": stringify(public_ipv6),
        "private_ipv6": stringify(private_ipv6),
        "first_ip": first_ip(
            public_ipv4,
            public_ipv6,
            private_ipv4,
            private_ipv6
        ),
    }

class ShodanHostDetailsParser: 
    # The 'parse_host_details' function takes an IP address as input and retrieves details about that IP address using the Shodan API.
    # It prints various details about the IP address, such as the organization, operating system, last update, number of open ports,
    # vulnerabilities, hostnames, ISP, city, country, latitude, longitude, ASN, certificates, and encryption algorithms.
    def parse_host_details(self, ip_address):
        """
        Print details about the IP address
        Args:
            ip_address (String): The IP address to scan
        """
        ipinfo = api.host(ip_address)
        json_data = json.loads(json.dumps(ipinfo))
        # ---------- Dedup containers ----------
        ssl_versions = set()
        cert_details = set()
        cipher_details = set()
        fingerprints = set()
        pubkeys = set()
        services = set()
        vulnerabilities = set()

        # ---------- Parse services ----------
        # We iterate through the services associated with the IP address, extracting relevant information about each service,
        # such as the port number, transport protocol, product name, and version.

        for service in json_data.get("data", []):
            port = service.get("port")
            transport = service.get("transport", "tcp")
            product = service.get("product")
            version = service.get("version")
            # We add the service information to the 'services' set, which includes the port number, transport protocol, product name, and version (if available).
            services.add(
                f"{port}/{transport} "
                f"{product or ''} {version or ''}".strip()
            )
            # We check if the service has SSL/TLS information available. If it does, we extract and print the relevant details about the SSL/TLS configuration,
            # such as the supported versions, cipher information, certificate details, fingerprints, public key information, and any detected vulnerabilities.
            ssl = service.get("ssl")
            if not ssl:
                continue
            else:
                print(f"\n--- SSL/TLS Service on port {port} ---")

            # SSL Versions
            for v in ssl.get("versions", []):
                ssl_versions.add(v)
            else:
                print("No SSL/TLS versions detected or no SSL version information available.")

            # Cipher info
            cipher = ssl.get("cipher")
            if cipher:
                cipher_details.add(
                    f"{cipher.get('version')} | "
                    f"{cipher.get('name')} | "
                    f"{cipher.get('bits')} bits"
                )
            else:   
                cipher_details.add("No cipher information available.")

            # Certificate info
            cert = ssl.get("cert")
            if cert:
                cert_details.add(
                    f"sig_alg={cert.get('sig_alg')} | "
                    f"issued={cert.get('issued')} | "
                    f"expires={cert.get('expires')} | "
                    f"expired={cert.get('expired')} | "
                    f"version={cert.get('version')}"
                )
            else:
                cert_details.add("No certificate information available.")

            # Fingerprints
            fp = cert.get("fingerprint", {})
            if fp.get("sha256"):
                fingerprints.add(f"SHA256: {fp['sha256']}")
            if fp.get("sha1"):
                fingerprints.add(f"SHA1: {fp['sha1']}")
            else:
                fingerprints.add("No fingerprint information available.")

            # Public key
            pubkey = cert.get("pubkey")
            if pubkey:
                pubkeys.add(
                    f"{pubkey.get('type')} | {pubkey.get('bits')} bits"
                )
            else:
                pubkeys.add("No public key information available.")
                
            # Vulnerabilities
            vulns = cert.get("vulns", [])
            for v in vulns:
                vulnerabilities.add(v)
            if vulns:
                vulnerabilities.update(vulns)
            else:
                vulnerabilities.add("No vulnerabilities detected or no vulnerability information available.")

        # Print details
        # We print various details about the IP address, such as the organization, operating system, last update, number of open ports,
        # vulnerabilities, hostnames, ISP, city, country, latitude, longitude, ASN, certificates, and encryption algorithms.
        # This information provides valuable insights into the target's network and security posture, allowing for further analysis and potential exploitation.
        # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
        # We ensure that the user is aware of the available information and encourage them to use it for further reconnaissance and analysis.

        print(f"IP: {json_data.get('ip_str', 'n/a')}")
        print(f"Organization: {json_data.get('org', 'n/a')}")
        print(f"Last Update: {json_data.get('last_update', 'n/a')}")
        print(f"City: {json_data.get('city', 'n/a')}")
        print(f"Country: {json_data.get('country_name', 'n/a')}")
        print(f"Open Ports: {', '.join(str(p) for p in json_data.get('ports', []))}")

        print("\n--- Services ---")
        if not services:
            print("No services detected or no service information available.")
        else:
            for s in sorted(services):
                print(f"  {s}")

        print("\n--- SSL Versions ---")
        print(", ".join(sorted(ssl_versions)) or "No SSL/TLS services detected or no SSL version information available.")

        print("\n--- Ciphers ---")
        if not cipher_details:
            print(" No SSL/TLS services detected or no cipher information available.")
        else:
            for c in sorted(cipher_details):
                print(f"  {c}")

        print("\n--- Certificates ---")
        if not cert_details:
            print("No Certificates detected or no certificate information available.")
        else:
            for c in cert_details:
                print(f"  {c}")

        print("\n--- Public Keys ---")
        if not pubkeys:
            print("No Public Keys detected or no public key information available.")
        else:
            for p in pubkeys:
                print(f"  {p}")

        print("\n--- Fingerprints ---")
        if not fingerprints:
            print("No Fingerprints detected or no fingerprint information available.")
        else:
            for f in fingerprints:
                print(f"  {f}")

        print ("\n--- Vulnerabilities ---")
        if not vulnerabilities:
            print("No Vulnerabilities detected or no vulnerability information available.")
        else:
            for v in vulnerabilities:
                print(f"  {v}")

# The main loop for the information gathering tool presents a menu to the user and executes the corresponding actions based on the user's choice.
# It allows the user to perform DNS reconnaissance, Shodan hacking, or network reconnaissance by selecting the appropriate option from the menu.
if __name__ == "__main__":
    # Main loop for the information gathering tool.
    # It presents a menu to the user and executes the corresponding actions based on the user's choice.
    while(iterate != 4):
        print("\n--------------------------------------------")
        print("Welcome to our Information Gathering Tool!!!")
        print("---------------------------------------------")
        print("Please make sure to follow the on-screen menu")
        print("---------------------------------------------")
        print("Option 1: DNS Reconnaissance")
        print("Option 2: Shodan Hacking")
        print("Option 3: Network Reconnaissance")
        print("EXIT.........................................")
        print("---------------------------------------------")
        # We prompt the user to enter an option from the menu.
        # The input is converted to an integer for easier comparison in the subsequent if-elif statements.
        options = int(input("Please enter any option from the list above.\n"))
        # Based on the user's input, we execute the corresponding actions for DNS reconnaissance, Shodan hacking, or network reconnaissance.
        # If the user selects an option that is not listed, we exit the program gracefully, wishing the user a nice day.
        # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
        # We ensure that the user is aware of the available options and encourage them to use the tool for optimal results in their information gathering and reconnaissance tasks.
        if (options == 1):
            print("\n-----------------------------------------\n")
            print("\tDNS Reconaissance\t")
            print("\n-----------------------------------------\n")
            # We prompt the user to enter their target for DNS reconnaissance.
            # The input is stored in the variable 'target' for later use in executing the appropriate commands based on the user's operating system.
            # This allows the user to easily specify the target they want to gather DNS information about, providing a seamless and interactive experience for performing DNS reconnaissance tasks.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            target = input(f"Enter your target: ")
            # For Windows, we utilize the NSLOOKUP command to perform DNS reconnaissance.   
            # We execute various NSLOOKUP commands to gather different types of DNS information,    
            # such as MX records, SOA records, AAAA records, A records, PTR records, NS records, and CNAME records.     
            # The output of each command is captured and displayed to the user in a formatted manner.
            # This allows the user to easily access and understand the DNS information related to their target, providing valuable insights for further reconnaissance and analysis.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            if (System_version.system == "Windows"):
                email_output = subprocess.run(["nslookup", "-type=mx", target], capture_output=True, text=True)
                soa_output = subprocess.run(["nslookup", "-type=soa", target], capture_output=True, text=True)
                aaaa_output = subprocess.run(["nslookup", "-type=AAAA", target], capture_output=True, text=True)
                a_output = subprocess.run(["nslookup", "-type=A", target], capture_output=True, text=True)
                ptr_output = subprocess.run(["nslookup", "-type=PTR", target], capture_output=True, text=True)
                ns_output = subprocess.run(["nslookup", "-type=NS", target], capture_output=True, text=True)
                cname_output = subprocess.run(["nslookup", "-type=CNAME", target], capture_output=True, text=True)

                print("\n----------------------------------------\n")
                print("\tNSLOOKUP (DNS INFO)\t")
                print("\n----------------------------------------\n")
                print("\n------------- A Record -----------------\n")
                print(a_output.stdout)
                print("\n----------- Quad A Record --------------\n")
                print(aaaa_output.stdout)
                print("------------- MX Record ------------------\n")
                print(email_output.stdout)
                print("---------- State of Authority ------------\n")
                print(soa_output.stdout)
                print("------------- PTR Record ----------------\n")
                print(ptr_output.stdout)
                print("------------- NS Record ----------------\n")
                print(ns_output.stdout)
                print("------------- CNAME Record --------------\n")
                print(cname_output.stdout)
                print("\n----------------------------------------\n")

            # For Linux, we provide the user with a choice between using DIG or WHOIS for DNS reconnaissance.
            # Based on the user's input, we execute the corresponding command and display the output.
            # The DIG command is used to gather detailed DNS information, while the WHOIS command is used to retrieve registration information about the target domain.
            # We ensure that the user is aware of the available options and provide clear instructions on how to use them for optimal results.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            elif (System_version.system == "Linux"):
                choice = input(f"Which tool do you want to utilise in Linux? (DIG or WHOIS): ")
                choice = choice.upper()  # Convert user input to uppercase for easier comparison

                if (choice == "DIG"):
                    dig_output = subprocess.run(["dig", target], capture_output=True, text=True)
                    print("\n----------------------------------------\n")
                    print("\t\tDIG INFO\t\t")
                    print("\n----------------------------------------\n")
                    print(dig_output.stdout)

                elif (choice == "WHOIS"):
                    whois_output = subprocess.run(["whois", target], capture_output=True, text=True)
                    print("\n----------------------------------------\n")
                    print("\t\tWHOIS SEARCH\t\t")
                    print("\n----------------------------------------\n")
                    print(whois_output.stdout)
                    print("\n----------------------------------------\n")
                # If the user enters an invalid option for Linux, we inform them that only DIG or WHOIS are available options for DNS reconnaissance on Linux.
                # We then exit the program gracefully, wishing the user a nice day.
                # This ensures that the user is aware of the limitations of the tool and encourages them to use it correctly for optimal results.
                # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
                else:
                    print("No other options available for Linux, Please choose DIG or WHOIS only!!!")
                    print("Exiting the program, Have a nice day!!!!")
                    print("\n----------------------------------------\n")
                    break
            # For other operating systems, we inform the user that their system is not supported for DNS reconnaissance and prompt them to try again with a different system
            # or check their system information.
            # We then exit the program gracefully, wishing the user a nice day.
            # This ensures that the user is aware of the limitations of the tool and encourages them to use it on a supported operating system for optimal results.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            else:
                System_version.system == "Other"
                print("Please try again with a different system or check your system information and try again!!!")
                print("Exiting the program, Have a nice day!!!!")
                print("\n----------------------------------------\n")
                break

        # If the user selects option 2 for Shodan Hacking, we prompt them to enter a target and then resolve all associated IP addresses using the 'resolve_all_ips' function.
        # We store the resolved IP addresses locally for later use in the program, allowing us to easily access the IP addresses for further reconnaissance tasks,
        # such as using the Shodan API to retrieve details about the target's IP address.
        # We then create an instance of the 'ShodanHostDetailsParser' class and call the 'parse_host_details' method with the first resolved IP address to retrieve
        # and display details about the target's IP address using the Shodan API.
        # This information provides valuable insights into the target's network and security posture, allowing for further analysis and potential exploitation.
        # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
        # We ensure that the user is aware of the available information and encourage them to use it for further reconnaissance and analysis.
        elif options == 2:
            print("\n-----------------------------------------\n")
            print("\tShodan Hacking\t")
            print("\n-----------------------------------------\n")

            target = input("Enter your target: ")
            ips = resolve_all_ips (target)

            # Storing the resolved IP addresses locally for later use in the program.
            # This allows us to easily access the IP addresses for further reconnaissance tasks,
            # such as using the Shodan API to retrieve details about the target's IP address.
            private_ipv4 = ips["private_ipv4"]
            private_ipv6 = ips["private_ipv6"]
            public_ipv4 = ips["public_ipv4"]
            public_ipv6 = ips["public_ipv6"]
            ip_address = ips["first_ip"]

            print("\n-----------------------------------------\n")
            # Note: The 'ShodanHostDetailsParser' class is responsible for parsing and displaying details about the target's IP address using the Shodan API.
            # Does detect the IPV6 addresses in Linux, but not in Windows,
            # which is a known issue with the Shodan API and may require additional configuration or troubleshooting to resolve.
            shodan_host_details_parser = ShodanHostDetailsParser()
            # We call the 'parse_host_details' method of the 'ShodanHostDetailsParser' class with the first resolved IP address to retrieve and 
            # display details about the target's IP address using the Shodan API.
            # This information provides valuable insights into the target's network and security posture, allowing for further analysis and potential exploitation.
            shodan_host_details_parser.parse_host_details(ip_address)

            print("\n-----------------------------------------\n")
        
        elif options == 3:
            print("\n-----------------------------------------\n")
            print("\tNetwork Reconnaissance\t")
            print("\n-----------------------------------------\n")

            target = input("Enter your target: ")
            ips = resolve_all_ips(target)

            # Store locally for later use
            private_ipv4 = ips["private_ipv4"]
            private_ipv6 = ips["private_ipv6"]
            public_ipv4 = ips["public_ipv4"]
            public_ipv6 = ips["public_ipv6"]
            ip_address = ips["first_ip"]

            # We print the resolved IP addresses for the target, categorizing them as public or private and as IPv4 or IPv6.
            # This information provides valuable insights into the target's network configuration and can be used for further reconnaissance tasks, 
            # such as testing connectivity, performing traceroutes, or analyzing network interfaces.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            print("\n-----------------------------------------\n")
            print("\tIP Information")
            print("\n-----------------------------------------\n")

            if public_ipv4:
                print(f"\tPublic IPv4: {public_ipv4}\n")
            else:
                print("\tNo Public IPv4 address found.\n")

            if private_ipv4:
                print(f"\tPrivate IPv4: {private_ipv4}\n")
            else:
                print("\tNo Private IPv4 address found.\n")

            if public_ipv6:
                print(f"\tPublic IPv6: {public_ipv6}\n")
            else:
                print("\tNo Public IPv6 address found.\n")

            if private_ipv6:
                print(f"\tPrivate IPv6: {private_ipv6}")
            else:
                print("\tNo Private IPv6 address found.")

            print("\n-----------------------------------------\n")

            # Based on the user's operating system, we execute different commands for network reconnaissance.
            # For Windows, we utilize commands like IPCONFIG, NETSTAT, ARP, and NETSH to gather various types of network information,
            # such as IP configuration, active network connections, ARP table, routing table, network interfaces, IP address information, connectivity tests, and traceroutes.
            # For Linux, we utilize commands like IFCONFIG, NETSTAT, ARP, ROUTE, and IP to gather similar types of network information, tailored to the Linux operating system.
            # For other operating systems, we inform the user that their system is not supported for network
            # reconnaissance and prompt them to try again with a different system or check their system information.
            # We then exit the program gracefully, wishing the user a nice day.
            # This ensures that the user is aware of the limitations of the tool and encourages them to use it on a supported operating system for optimal results.
            # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
            # We ensure that the user is aware of the available information and encourage them to use it for further reconnaissance and analysis.
            if System_version.system == "Windows":
                print("\n-----------------------------------------\n")
                print ("\tActive Network Reconnaissance\t")
                print("\nWindows system detected, using Windows commands for network reconnaissance.")
                print("\n-----------------------------------------\n")
                print("\nIP Configuration:")
                ip_config_output = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
                print(ip_config_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nActive Network Connections:")
                netstat_active_network_connections = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
                print(netstat_active_network_connections.stdout)
                print("\n-----------------------------------------\n")
                print("\nARP Table:")
                arp_table_output = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                print(arp_table_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nRouting Table:")
                routing_table_output = subprocess.run(["netsh", "interface", "ip", "show", "config"], capture_output=True, text=True)
                print(routing_table_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nNetwork Interfaces:")
                network_interfaces_output = subprocess.run(["netsh", "interface", "ip", "show", "interface"], capture_output=True, text=True)
                print(network_interfaces_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nIP Address Information:")
                ip_address_info_output = subprocess.run(["netsh", "interface", "ip", "show", "ip"], capture_output=True, text=True)
                print(ip_address_info_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nTest Connectivity:")
                test_connectivity_output = subprocess.run(["ping",target], capture_output=True, text=True)
                print(test_connectivity_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nTraceroute:")
                trace_route_output = subprocess.run(["tracert", target], capture_output=True, text=True)
                print(trace_route_output.stdout)
                print("\n-----------------------------------------\n")
                
                # Active network reconnaissance commands for Windows include:
                # 1. IP Configuration: `ipconfig /all` - Displays detailed information about the network interfaces and their configurations.
                # 2. Active Network Connections: `netstat -an` - Shows all active network connections and listening ports.
                # 3. ARP Table: `arp -a` - Displays the Address Resolution Protocol (ARP) table, which maps IP addresses to MAC addresses.
                # 4. Routing Table: `netsh interface ip show config` - Displays the routing table and network configuration.
                # 5. Network Interfaces: `netsh interface ip show interface` - Shows the status and details of network interfaces.
                # 6. IP Address Information: `netsh interface ip show ip` - Displays detailed information about IP addresses assigned to interfaces.
                # 7. Test Connectivity: `ping <target>` - Tests the connectivity to the target by sending ICMP echo requests.
                # 8. Traceroute: `tracert <target>` - Traces the route taken by packets to reach the target, showing each hop along the way.
                # These commands provide valuable insights into the target's network configuration and can be used for further reconnaissance tasks,
                # such as analyzing network interfaces, testing connectivity, or performing traceroutes.
            elif System_version.system == "Linux":
                print("\n-----------------------------------------\n")
                print("\tActive Network Reconnaissance\t")
                print("\nLinux system detected, using Linux commands for network reconnaissance.")
                print("\n-----------------------------------------\n")
                print("\nIP Configuration:")
                if_config_output = subprocess.run(["ifconfig"], capture_output=True, text=True)
                print(if_config_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nActive Network Connections:")
                network_active_networks_output = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
                print(network_active_networks_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nARP Table:")
                arp_tables_output = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                print(arp_tables_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nRouting Table:")
                routing_table_output = subprocess.run(["route", "-n"], capture_output=True, text=True)
                print(routing_table_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nNetwork Interfaces:")
                network_interfaces_output = subprocess.run(["ip", "link"], capture_output=True, text=True)
                print(network_interfaces_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nIP Address Information:")
                ip_address_info_output = subprocess.run(["ip", "addr"], capture_output=True, text=True)
                print(ip_address_info_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nTest Connectivity:")
                test_connectivity_output = subprocess.run(["ping", target], capture_output=True, text=True)
                print(test_connectivity_output.stdout)
                print("\n-----------------------------------------\n")
                print("\nTraceroute:")
                trace_route_output = subprocess.run(["traceroute", target], capture_output=True, text=True)
                print(trace_route_output.stdout)     
                print("\n-----------------------------------------\n")
            
            # Other operating systems are not supported for network reconnaissance, and we inform the user accordingly,
            # prompting them to try again with a different system or check their system information.
            else:
                System_version.system == "Other"
                print("\n-----------------------------------------\n")
                print("Please try again with a different system or check your system information and try again!!!")
                print("Exiting the program, Have a nice day!!!!")
                print("\n-----------------------------------------\n")
        # If the user selects an option that is not listed (i.e., not 1, 2, or 3), we exit the program gracefully, wishing the user a nice day.
        # This ensures that the user is aware of the available options and encourages them to use the tool correctly for optimal results.
        # The program is designed to be user-friendly and informative, providing clear instructions and feedback to the user throughout the process.
        else:
            print ("\n-----------------------------------------\n")
            print ("Exiting the program, Have a nice day!!!!")
            print ("\n-----------------------------------------\n")
            break
        iterate +=1

 
