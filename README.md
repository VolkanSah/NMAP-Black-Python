# NMAP-Black-Python (Example)
##### RedTeam Black-Python Scripts by Volkan Sah - simple codings for 'Offensive Security' (Update 2023)
###### This is a part of the how-to: Kill the onion!
**⚠️ WARNING: This tool is intended for educational and ethical hacking purposes only. Scanning networks without permission can be illegal and may result in criminal charges. Use this tool responsibly and only on networks you have permission to access. ⚠️**

NMAP-Black-Python is a Python script designed to automate the process of scanning networks for vulnerabilities and open ports using Nmap. This script reads domain names from a text file, scans them using Nmap, and stores the results in a CSV file for easy analysis. 

## How to Use
- Prepare a text file (e.g. domainlist.txt) containing the domains you want to scan, with one domain per line. This file should include both local and external domains, as well as local addresses such as 127.0.0.1:8080 for tor tunneling purposes, if necessary.
- Use Python to read the text file and extract the domain names. Python's built-in file handling functions, such as open() and readlines(), can be used to read the text file and store the domain names in a list.
- Iterate through the list of domain names and use the subprocess module in Python to execute Nmap commands with the appropriate options for scanning vulnerabilities and open ports. The -p option can be used to specify the ports to scan, and the -oX option can be used to output the results in XML format.
- Parse the XML output of Nmap using Python's built-in XML parsing libraries, such as xml.etree.ElementTree, to extract relevant information, such as open ports and vulnerabilities.
- Store the extracted information in a CSV file using Python's csv module, which enables writing data to a CSV file in a structured format.
- Once the scanning and parsing process is complete, analyze the results in the CSV file to identify vulnerabilities and open ports in the networks.

## Example

```
import subprocess
import csv
import xml.etree.ElementTree as ET

# Read the text file with domain names
with open('domainlist.txt', 'r') as file:
    domain_list = file.readlines()
    domain_list = [domain.strip() for domain in domain_list]

# Loop through domain names and perform Nmap scanning
for domain in domain_list:
    # Run Nmap command and capture output
    # Set wich ports you want scan for faster results
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

    # Write extracted information to CSV cause we need always only .txt or .csv
    with open(f'{domain}.csv', 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'Open Ports', 'Vulnerabilities']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Domain': domain, 'Open Ports': ', '.join(open_ports), 'Vulnerabilities': ', '.join(vulnerabilities)})
        
        
        // get csv output use next script /tool or exucute your own handel with the information 
``` 
## License
This project is licensed under the MIT License. See LICENSE file for more information.

## Credits
NMAP-Black-Python was created and is maintained by [Volkan Sah](https://github.com/volkansah)

## Disclaimer
The developer of NMAP-Black-Python is not responsible for any misuse or damage caused by this tool. It is the user's responsibility to ensure that they have the necessary permissions to use this tool on their chosen networks.

## Issues
Issues to this script are not accepted as it is intended for educational purposes only and not for production use.

## WARNING! AGAIN!
**⚠️ WARNING: Scanning networks without permission can be illegal and may result in criminal charges. Use this tool responsibly and only on networks you have permission to access. By using NMAP-Black-Python, you agree to use it for educational and ethical hacking purposes only. ⚠️**
