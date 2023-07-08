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
