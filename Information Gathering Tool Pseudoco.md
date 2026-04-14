**Pseudocode for Information Gathering Tool**

Initialization

\# Determine OS and version

Your\_OS         ← platform.platform(terse=True)

System\_version ← platform.uname()



\# Loop counter

iterate ← 0



\# Initialize Shodan API client

api ← Shodan("YOUR\_API\_KEY")

Function: resolve\_all\_ips(target)

function resolve\_all\_ips(target):

&nbsp;   Initialize lists:

&nbsp;       public\_ipv4, private\_ipv4, public\_ipv6, private\_ipv6 ← empty lists



&nbsp;   define add\_unique(list, item):

&nbsp;       if item not in list:

&nbsp;           append item



&nbsp;   # Case 1: Target is a literal IP address

&nbsp;   try:

&nbsp;       ip ← parse IP address from target

&nbsp;       if ip.version == 4:

&nbsp;           if ip.is\_global then add\_unique(public\_ipv4, ip) 

&nbsp;                           else add\_unique(private\_ipv4, ip)

&nbsp;       else:

&nbsp;           if ip.is\_global then add\_unique(public\_ipv6, ip)

&nbsp;                           else add\_unique(private\_ipv6, ip)

&nbsp;   catch ValueError:

&nbsp;       # Case 2: Target is a hostname

&nbsp;       try:

&nbsp;           for each result in socket.getaddrinfo(target, AF\_INET):

&nbsp;               ip ← parse IP address from result

&nbsp;               categorize into public\_ipv4 or private\_ipv4

&nbsp;       catch:

&nbsp;           pass

&nbsp;       try:

&nbsp;           for each result in socket.getaddrinfo(target, AF\_INET6):

&nbsp;               ip ← parse IP address from result

&nbsp;               categorize into public\_ipv6 or private\_ipv6

&nbsp;       catch:

&nbsp;           pass



&nbsp;   if all lists are empty:

&nbsp;       print "\[-] Failed to resolve target."



&nbsp;   define stringify(list):

&nbsp;       return first element or empty string



&nbsp;   define first\_ip(groups...):

&nbsp;       for each group in groups:

&nbsp;           if group not empty:

&nbsp;               return group\[0]

&nbsp;       return empty string



&nbsp;   return dictionary:

&nbsp;       public\_ipv4    ← stringify(public\_ipv4)

&nbsp;       private\_ipv4   ← stringify(private\_ipv4)

&nbsp;       public\_ipv6    ← stringify(public\_ipv6)

&nbsp;       private\_ipv6   ← stringify(private\_ipv6)

&nbsp;       first\_ip       ← first\_ip(public\_ipv4, public\_ipv6, private\_ipv4, private\_ipv6)

Class: ShodanHostDetailsParser

class ShodanHostDetailsParser:

&nbsp;   method parse\_host\_details(ip\_address):

&nbsp;       ipinfo    ← api.host(ip\_address)

&nbsp;       json\_data ← convert ipinfo to JSON



&nbsp;       Initialize sets:

&nbsp;           ssl\_versions, cert\_details, cipher\_details,

&nbsp;           fingerprints, pubkeys, services, vulnerabilities



&nbsp;       for each service in json\_data\["data"]:

&nbsp;           port      ← service\["port"]

&nbsp;           transport ← service.get("transport", "tcp")

&nbsp;           product   ← service.get("product")

&nbsp;           version   ← service.get("version")



&nbsp;           add formatted service info to services set



&nbsp;           if service contains "ssl":

&nbsp;               print header for SSL on port

&nbsp;               extract and add:

&nbsp;                   versions → ssl\_versions

&nbsp;                   cipher info → cipher\_details

&nbsp;                   certificate info → cert\_details

&nbsp;                   fingerprints → fingerprints

&nbsp;                   public key info → pubkeys

&nbsp;                   vulnerabilities → vulnerabilities



&nbsp;       # Print summary details

&nbsp;       print ip, organization, city, country, last\_update, open\_ports



&nbsp;       print "--- Services ---"

&nbsp;       iterate sorted(services)



&nbsp;       print "--- SSL Versions ---"

&nbsp;       iterate sorted(ssl\_versions)



&nbsp;       print "--- Ciphers ---"

&nbsp;       iterate sorted(cipher\_details)



&nbsp;       print "--- Certificates ---"

&nbsp;       iterate cert\_details



&nbsp;       print "--- Public Keys ---"

&nbsp;       iterate pubkeys



&nbsp;       print "--- Fingerprints ---"

&nbsp;       iterate fingerprints



&nbsp;       print "--- Vulnerabilities ---"

&nbsp;       iterate vulnerabilities

Main Loop

while iterate ≠ 4:

&nbsp;   print menu:

&nbsp;       1: DNS Reconnaissance

&nbsp;       2: Shodan Hacking

&nbsp;       3: Network Reconnaissance

&nbsp;       any other: Exit



&nbsp;   options ← integer input



&nbsp;   if options == 1:

&nbsp;       # DNS Reconnaissance

&nbsp;       target ← user input



&nbsp;       if System\_version.system == "Windows":

&nbsp;           run nslookup for types: MX, SOA, AAAA, A, PTR, NS, CNAME

&nbsp;           display outputs grouped by record type



&nbsp;       else if System\_version.system == "Linux":

&nbsp;           choice ← input("DIG or WHOIS?").upper()

&nbsp;           if choice == "DIG":

&nbsp;               run `dig target` and display

&nbsp;           else if choice == "WHOIS":

&nbsp;               run `whois target` and display

&nbsp;           else:

&nbsp;               print error and break



&nbsp;       else:

&nbsp;           print unsupported OS and break



&nbsp;   else if options == 2:

&nbsp;       # Shodan Hacking

&nbsp;       target ← user input

&nbsp;       ips    ← resolve\_all\_ips(target)

&nbsp;       ip\_to\_scan ← ips\["first\_ip"]



&nbsp;       parser ← new ShodanHostDetailsParser()

&nbsp;       parser.parse\_host\_details(ip\_to\_scan)



&nbsp;   else if options == 3:

&nbsp;       # Network Reconnaissance

&nbsp;       target ← user input

&nbsp;       ips    ← resolve\_all\_ips(target)

&nbsp;       display public/private IPv4 and IPv6 from ips



&nbsp;       if System\_version.system == "Windows":

&nbsp;           run and display results for:

&nbsp;               ipconfig /all, netstat -an, arp -a,

&nbsp;               netsh interface ip show config,

&nbsp;               netsh interface ip show interface,

&nbsp;               netsh interface ip show ip,

&nbsp;               ping target, tracert target



&nbsp;       else if System\_version.system == "Linux":

&nbsp;           run and display results for:

&nbsp;               ifconfig, netstat -an, arp -a,

&nbsp;               route -n, ip link, ip addr,

&nbsp;               ping target, traceroute target



&nbsp;       else:

&nbsp;           print unsupported OS and break



&nbsp;   else:

&nbsp;       print exit message and break



&nbsp;   iterate ← iterate + 1

