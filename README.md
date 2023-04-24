# NMAP-Black-Python-Script

Prepare a text file (.txt) with the domains you want to scan, with one domain per line. This file should contain both local and external domains.

Use Python to read the text file and extract the domain names. You can use built-in file handling functions in Python, such as open() and readlines(), to read the text file and store the domain names in a list.

Iterate through the list of domain names and use subprocess module in Python to execute Nmap commands with the appropriate options for scanning vulnerabilities and open ports. You can use the -p option to specify the ports to scan, and the -oX option to output the results in XML format.

Parse the XML output of Nmap using Python's built-in XML parsing libraries, such as xml.etree.ElementTree, to extract the relevant information, such as open ports and vulnerabilities.

Store the extracted information in a CSV file using Python's CSV module, which allows you to write data to a CSV file in a structured format.

Once the scanning and parsing process is complete, you can analyze the results in the CSV file to identify vulnerabilities and open ports in your local network.

Here's an example:





```
import subprocess
import csv
import xml.etree.ElementTree as ET

# Read the text file with domain names
with open('domains.txt', 'r') as file:
    domain_list = file.readlines()
    domain_list = [domain.strip() for domain in domain_list]

# Loop through domain names and perform Nmap scanning
for domain in domain_list:
    # Run Nmap command and capture output
    cmd = f'nmap -p 1-65535 -oX {domain}.xml {domain}'
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)

    # Parse XML output
    tree = ET.parse(f'{domain}.xml')
    root = tree.getroot()

    # Extract relevant information from XML
    open_ports = []
    vulnerabilities = []
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            port_id = port.get('portid')
            open_ports.append(port_id)
        for script in host.findall('hostscript/script'):
            output = script.get('output')
            vulnerabilities.append(output)

    # Write extracted information to CSV
    with open(f'{domain}.csv', 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'Open Ports', 'Vulnerabilities']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Domain': domain, 'Open Ports': ', '.join(open_ports), 'Vulnerabilities': ', '.join(vulnerabilities)})






``` 
