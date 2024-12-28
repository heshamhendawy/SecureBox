# SecureBox
 Cybersecurity-Automated TOOL
 
 All rights reserved. Unauthorized use of this project is prohibited.
 
## License

This project is proprietary software. All rights are reserved by M0stafa0x10. 
No part of this software may be used, copied, modified, distributed, or incorporated into other projects without explicit written permission from the owner.

For licensing inquiries, please contact: [engmostafa.mohamed9@gmail.com].



# Introduction
In today's interconnected world, cybersecurity is paramount. SecureBox is a powerful, all-in-one cybersecurity toolkit designed to empower you with the ability to proactively identify and mitigate vulnerabilities in your systems. From network port scanning and exploitation to advanced web application security testing, SecureBox provides the tools you need to stay one step ahead of potential threats. All the previous functions has a final result that is recorded in a file, (Port scanning, exploitation, and SQL Injection) in PDF File manually that you go to generate report window and click generate report, XSS Injection are recorded in json file automatically.


# Top Functions
- Port Scanning
- Port Exploitation
- SQL Injection (Automatic OR Manual)
- XSS Injection (Automatic OR Manual)

# Port Scanning
This is the process of identifying active ports on a target device. Ports are communication channels used by applications and services to exchange data. By scanning ports, you can understand what services are running on a machine and potentially discover vulnerabilities

# Port Expolitation
After identifying open ports, we may attempt to exploit known vulnerabilities in the services running on those ports as: [FTP - Telnet - SSH] to brute force that known machine to know the username and password. It's preferred that you make your own wordlist file to be able to make this service and attaack. This could involve sending specially crafted data packets or code to take control of the system, steal data, or disrupt operations. It can then attempt to exploit those ports using pre-defined techniques for common services like Telnet, FTP, and SSH.

# SQL Injection
This vulnerability occurs when user input is not properly sanitized before being used in an SQL query. We can inject malicious SQL code that can manipulate the database, steal sensitive data, or even take control of the database server.  It doesn't directly perform SQL injection attacks, but it offers features to support manual testing through a request file and potentially identify potential vulnerabilities based on responses.


# XSS Injection
This is a type of web application vulnerability that allows attackers to inject malicious scripts into web pages. When a user visits the infected page, the script executes in their browser, potentially stealing data, redirecting them to malicious sites, or altering the content they see. The application provides tools to help identify and exploit XSS vulnerabilities in web applications. This may involve loading payloads (malicious code) and testing them against forms or other user input points.


# Install Ubuntu & Debian Destributions
<pre>
 <span style="color: green;">
  sudo git clone https://github.com/heshamhendawy/SecureBox.git
 </span>
</pre>

<h5> Install Requirements (Manually) </h5>
<pre>
 <span style="color: green;">
  sudo pip install python-nmap --break-system-packages
  sudo pip install bs4 --break-system-packages
  sudo pip install requests --break-system-packages
  sudo pip install fpdf --break-system-packages
  sudo pip install paramiko --break-system-packages
  sudo apt-get install python3-tk --break-system-packages
 </span>
</pre>

<h5> Install Requirements (Automatically) </h5>
<pre>
 <span style="color: green;">
  sudo pip install -r requirements.txt
 </span>
</pre>

<h5> Run the Script </h5>
<pre>
 <span style="color: green";>
  cd SecureBox
  sudo chmod +x SecureBox.py
  ls -l SecureBox.py
  sudo python3 SecureBox.py
 </span>
</pre>

# Install Windows
<h5>
 You can install the zip folder and run the script on any compiler you have such as PyCharm or VS Code.
 Make sure to install the missed libraries found in the requirements.txt file in your compiler's terminal.
</h5>

# Hope you enjoy. Thank You
