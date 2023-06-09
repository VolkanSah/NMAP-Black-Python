# NMAP-Black-Python (lite)
###### If forked please check for updates https://github.com/VolkanSah/NMAP-Black-Python
![NMAP Black Python by Volkan Sah](nmap-blackpython.png)

##### RedTeam Black-Python Scripts by Volkan Sah - simple codings for 'Offensive Security' (Update 2023)
**⚠️ WARNING: This tool is intended for educational and ethical hacking purposes only. Scanning networks without permission can be illegal and may result in criminal charges. Use this tool responsibly and only on networks you have permission to access. ⚠️**

NMAP-Black-Python is a Python script designed to automate the process of scanning networks for vulnerabilities and open ports using Nmap. This script reads domain names from a text file, scans them using Nmap, and stores the results in a CSV file for easy analysis. This is a part of the lesson "how to kill the pudding"

## How to Use
- Prepare a text file (e.g. domainlist.txt) containing the domains you want to scan, with one domain per line. This file should include both local and external domains, as well as local addresses such as 127.0.0.1:8080 for tor tunneling purposes, if necessary.
- Use Python to read the text file and extract the domain names. Python's built-in file handling functions, such as open() and readlines(), can be used to read the text file and store the domain names in a list.
- Iterate through the list of domain names and use the subprocess module in Python to execute Nmap commands with the appropriate options for scanning vulnerabilities and open ports. The -p option can be used to specify the ports to scan, and the -oX option can be used to output the results in XML format.
- Parse the XML output of Nmap using Python's built-in XML parsing libraries, such as xml.etree.ElementTree, to extract relevant information, such as open ports and vulnerabilities.
- Store the extracted information in a CSV file using Python's csv module, which enables writing data to a CSV file in a structured format.
- Once the scanning and parsing process is complete, analyze the results in the CSV file to identify vulnerabilities and open ports in the networks.

## Example code
This script is intended for educational and ethical hacking purposes only

```
# NPM Black Python (lite)
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
    # Set ports you want scan with nmap for faster results
    cmd = f'nmap -p 1-65535 -oX {domain}.xml {domain}'
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    
    # Removed #########################################################
    # logic ='removed to prevent abuse please create your own logic!' #
    # logics tipp: Hydra can handel 64 Proxies/Tunnels at on time and #
    # Nikto loves to work with MSF+ i mean they cam mary :smile:#     #
    # Without this logic this script is powerfull enought for research#
    # No quesstion please, you must learn programming logic           #
    ###################################################################
    
    # Parse XML output
    tree = ET.parse(f'{domain}.xml')
    root = tree.getroot()

    # Extract all relevant information from XML
    open_ports = []
    vulnerabilities = []
    for host in root.findall('host'):
        for port in host.findall('ports/port'):
            port_id = port.get('portid')
            open_ports.append(port_id)
        for script in host.findall('hostscript/script'):
            output = script.get('output')
            vulnerabilities.append(output)
            
    # Work finished ! you can handelnow the .xml or u export it to csv below  
    # you can use .join(open_ports)  or .join(vulnerabilities) handel with your on script with the xml with your own logic
    
    ###############################################
    # Handel removed! Creat your own!    ###########
    ###############################################
    
    # or write extracted information to CSV  (needed if you want use in other tools, cause they need most time .txt or .csv 
    with open(f'{domain}.csv', 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'Open Ports', 'Vulnerabilities']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'Domain': domain, 'Open Ports': ', '.join(open_ports), 'Vulnerabilities': ', '.join(vulnerabilities)})
        
       
    ## get csv output and use it in your next script /tool or exucute your own handel/mechanizem
    
``` 

## Issues
Issues to this script are not accepted as it is intended for educational purposes only and not for production use.

## WARNING! AGAIN!
**⚠️ WARNING: Scanning networks without permission can be illegal and may result in criminal charges. Use this tool responsibly and only on networks you have permission to access. By using NMAP-Black-Python, you agree to use it for educational and ethical hacking purposes only. ⚠️**


## Disclaimer
The developer of NMAP-Black-Python is not responsible for any misuse or damage caused by this tool. It is the user's responsibility to ensure that they have the necessary permissions to use this tool on their chosen networks.


### Thank you for your support!
- If you appreciate my work, please consider [becoming a 'Sponsor'](https://github.com/sponsors/volkansah), giving a :star: to my projects, or following me. 
### Copyright
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)

### License
This project is licensed under the MIT - see the [LICENSE](LICENSE) file for details


