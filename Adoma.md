#  INTERNAL PENETRATION TEST



Submitted by:
Name...


## Table of Contents

- [INTERNAL PENETRATION TEST](#internal-penetration-test)
  - [Table of Contents](#table-of-contents)
    - [Executive Summary](#executive-summary)
    - [Analysis of Overall Security Posture](#analysis-of-overall-security-posture)
    - [Key Recommendations](#key-recommendations)
    - [Testing Methodology](#testing-methodology)
    - [HOSTS DISCOVERY](#hosts-discovery)
        - [SUBDOMAIN ENUMERATION](#subdomain-enumeration)
    - [SERVICE DISCOVERY](#service-discovery)
          - [NMAP,SERVICE DISCOVERY \& PORT SCANNING](#nmapservice-discovery--port-scanning)
          - [Nmap Service Discovery Output](#nmap-service-discovery-output)
    - [VULNERABILITY SCANNING](#vulnerability-scanning)
        - [DETAILED FINDINGS](#detailed-findings)
          - [APACHE 2.4.49(SSL \& HTTP)](#apache-2449ssl--http)
        - [Finding Summary](#finding-summary)
        - [Evidence](#evidence)
        - [Affected Resources:](#affected-resources)
        - [Recommendations:](#recommendations)
        - [References:](#references)
          - [SQL 5.6.49 (mysql)](#sql-5649-mysql)
        - [Finding Summary](#finding-summary-1)
        - [Evidence](#evidence-1)
        - [Affected Resources:](#affected-resources-1)
        - [Recommendations:](#recommendations-1)
        - [References:](#references-1)
          - [RealVNC 5.3.2 (vnc)](#realvnc-532-vnc)
        - [Finding Summary](#finding-summary-2)
        - [Evidence](#evidence-2)
        - [Affected Resources:](#affected-resources-2)
        - [Recommendations:](#recommendations-2)
        - [References:](#references-2)
          - [rdp MICROSOFT TERMINAL SERVICES (rdp)](#rdp-microsoft-terminal-services-rdp)
        - [Finding Summary](#finding-summary-3)
        - [Evidence](#evidence-3)
        - [Affected Resources:](#affected-resources-3)
        - [Recommendations:](#recommendations-3)
        - [References:](#references-3)
    - [WEB-BASED ATTACK SURFACES](#web-based-attack-surfaces)
          - [Eyewitness Output](#eyewitness-output)
          - [PAYLOAD GENERATION](#payload-generation)
___

### Executive Summary

I performed a penetration test which was conducted on the internal network with the IP range 10.10.10.0/24. This was designed to uncover vulnerabilities and assess the overall security posture. The assessment utilized a comprehensive approach, incorporating host and service discovery, vulnerability scanning, and web-based surface attacks.

Initially, using the Nmap tool for host and service discovery, I mapped the active systems and the services they were running. This scan identified several key systems with exposed services, some of which were running outdated or insecure versions, raising concerns about potential entry points for attackers.

Following this, a vulnerability scan was performed using Metasploit, which revealed multiple critical and high-risk vulnerabilities within the network. Notably, there were several instances of unpatched software and configuration weaknesses that could be leveraged by malicious actors to gain unauthorized access or cause harm.

Additionally, I conducted a web-based surface attack assessment using the Eyewitness tool. This assessment pinpointed various security issues, including default credentials and potentially exploitable web interfaces, which could be targeted to compromise the system further.

The findings of this penetration test highlight several areas of concern: critical vulnerabilities due to outdated software, insecure configurations, and weak or default passwords. Immediate actions are recommended, including patching identified vulnerabilities, strengthening password policies, and regularly updating system configurations. These measures are crucial to enhance the security of the internal network and mitigate potential risks.


___
### Analysis of Overall Security Posture

The internal network assessment reveals a concerning security posture, characterized by several critical vulnerabilities and systemic weaknesses. The host and service discovery phase identified multiple systems with exposed services, some of which were running outdated software. This exposure significantly heightens the risk of exploitation, as outdated services are often targets for known vulnerabilities. The vulnerability scan further compounded these concerns by uncovering a range of high-risk vulnerabilities, including unpatched software and misconfigurations, which could be exploited by attackers to gain unauthorized access or disrupt operations. 

The web-based surface attack assessment highlighted additional risks, such as the presence of default credentials and insecure web interfaces, which could provide an easy entry point for malicious actors. Overall, the network exhibits multiple security flaws that undermine its resilience against potential threats. Immediate remediation is essential, including the application of security patches, improvement of password policies, and ongoing configuration management. Addressing these issues will be critical in strengthening the network's defenses and safeguarding against potential security breaches.

___

### Key Recommendations

- Implement a comprehensive patch management process to ensure up-to-date security.
- Strengthen authentication mechanisms by enforcing strong password policies and using multi-factor authentication (MFA).
- Prioritize configuration hardening to secure system settings and reduce attack surfaces.
- Integrate regular vulnerability scanning into a continuous monitoring strategy.
- Conduct regular security awareness training for employees.
- Enhance web application security with web application firewalls (WAFs) and periodic assessments.
- Develop and maintain a robust incident response plan, regularly tested and updated.

___

### Testing Methodology

The testing methodology for the internal network penetration assessment followed a structured approach to comprehensively evaluate the security posture. The initial phase involved Host and Service Discovery using Nmap. This step aimed to map the network by identifying active hosts and the services running on them. The Nmap tool was utilized to perform a detailed scan of the IP range 10.10.10.0/24, revealing open ports and services, which laid the groundwork for identifying potential vulnerabilities.
Following discovery, the Vulnerability Scanning phase was conducted using Metasploit. This phase focused on analyzing the identified services and systems for known vulnerabilities. Metasploit’s capabilities enabled the detection of critical and high-risk vulnerabilities, including outdated software and misconfigurations. The results from this scan were essential for understanding the potential attack vectors and the overall risk exposure of the network.
The final phase of the assessment involved Web-Based Surface Attacks using the Eyewitness tool. This tool was used to evaluate the security of web applications and services by identifying potential weaknesses such as default credentials and insecure web interfaces. The findings from this phase provided insights into possible exploitation points and highlighted areas requiring immediate attention. Overall, the combination of these methodologies provided a thorough evaluation of the network’s security landscape, guiding the development of targeted remediation strategies.



___

### HOSTS DISCOVERY

The Nmap tool was use to scan for the host available in the network scope. The command used for the host discovery is shown below:

![hostdiscover](/assets/hostdiscover.jpg)

The output from the host discovery was then filtered to get their IP Addresses. The host discovery filter by using the **grep** and **awk** commands is shown below:

![hostfilter](/assets/hostfilter1.jpg)

##### SUBDOMAIN ENUMERATION

The subdomain enumeration was done using the **aiodnsbrute** on the hosts in the network scope(10.10.10.1/24)

![aiodnsbrute](/assets/aiodnsbrute.jpg)

___

### SERVICE DISCOVERY

The service discovery helps for the identification and understanding of the services running on the network and the ports they're using and also provide an insight into the network's attack surface.

**Service Discovery** also helps to identify which services are running on specific devices along with their versions enabling testers to pinpoint any known vulnerabilities associated with those services which could serve as entry point for attackers.

**Port Scanning** identifies open ports which serves as gateway for communication between devices by finding this open ports testers can define which services are accessible and possess potential vulnerabilities. For an instance,an open port running an outdated or misconfigured service could provide attacks with a direct path to exploit the network.

###### NMAP,SERVICE DISCOVERY & PORT SCANNING

The Service Discovery and Port Scanning was done using the Nmap tool. The command and output with the various file outputs are shown below: 

![NmapService](/assets/nmapservice.jpg)

The **HTTP** service scan discovery using the nmap tool is show below:

![NmapServiceHttp](/assets/nmapservice_http.jpg)

###### Nmap Service Discovery Output

![nmapserviceoutput](/assets/servicescantype.png)

---

### VULNERABILITY SCANNING
##### DETAILED FINDINGS



###### APACHE 2.4.49(SSL & HTTP)

*Apache 2.4.49 Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         8.8    |

##### Finding Summary
It was found that there was improper input validation on **APACHE HTTP SERVER 2.24.49**. Misconfigurations and improper input validation could expose the server to various types of attacks such as injection attacks;which is injecting malicious code into thep program's input which can later be executed by the program


##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the HTTP server which is shown below:

![apache http](/assets/apachehttp.png)

##### Affected Resources:

  10.10.10.2,  10.10.10.30,   10.10.10.45,      10.10.10.55


##### Recommendations:

* Upgrade Apache: Update to Apache HTTP Server 2.4.51 or later, which contains fixes for these vulnerabilities.
* Secure Aliased Directories: Ensure Alias and AliasMatch directives are correctly configured and protected. 
* Apply Require all denied where needed.
* Disable CGI Scripts: If CGI scripts are not required in aliased directories, disable them.
* Review Configurations: Regularly check and audit directory configurations and access controls.
* Implement Rate Limiting: Use modules like mod_evasive to control request rates and mitigate potential DoS attacks.
* Monitor Server Performance: Use monitoring tools to detect and respond to unusual server behavior.

##### References:

[https://www.cve.org/CVERecord?id=CVE-2021-42013](https://www.cve.org/CVERecord?id=CVE-2021-42013)



###### SQL 5.6.49 (mysql)

*MySQL 5.6.49  Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Medium      |         4.3    |

##### Finding Summary

CVE-2020-14672, this vulnerability allows an attacker to force an invalid signature,causing an assertion failure or possible validation.The highest threat to this vulnerability is to confidentiality,integrity as well as system availability which is the CIA triad 


##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the mySql server which is shown below:

![mysql img](/assets/mysql.png)

##### Affected Resources:

  10.10.10.5, 10.10.10.40


##### Recommendations:

* Upgrade MySQL:  Upgrade to the latest stable version of MySQL that includes fixes for these vulnerabilities. For MySQL 5.6 users, consider upgrading to a more recent, supported version such as MySQL 5.7.x or 8.0.x, if feasible. 
* Check for Patches: Review the MySQL release notes and apply any relevant security patches that address these vulnerabilities. Ensure that your system is patched with all available updates to mitigate the identified issues.
* Regular Backups: Maintain up-to-date backups of your MySQL databases. Ensure that backups are stored securely and can be quickly restored in the event of an attack or failure.
* Test Recovery Procedures: Periodically test your backup and recovery procedures to ensure they work as expected and can be executed quickly in an emergency.
* Restrict Network Access: Limit network access to your MySQL server using firewall rules or network segmentation. Only allow connections from trusted IP addresses and networks to reduce the risk of exploitation.

##### References:

[https://www.tenable.com/plugins/nessus/138571](https://www.tenable.com/plugins/nessus/138571)

###### RealVNC 5.3.2 (vnc)
*RealVNC 5.3.2   Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         7.8    |

##### Finding Summary

CVE-2015-7354:A vulnerability allowing unauthorized users to bypass authentication, potentially enabling access to the VNC server without valid credentials.



##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the realvnc server which is shown below:

![vnc img](/assets/vnc.png)

##### Affected Resources:

10.10.10.10, 10.10.10.50


##### Recommendations:

* Update VNC Viewer: Upgrade to the latest version of VNC Viewer that addresses the vulnerabilities identified in CVE-2020-14672 and CVE-2020-14673. Ensure you are using a version where these issues are patched.
* Review Authentication Settings: Regularly review and update authentication settings to align with best security practices and to prevent unauthorized access.
* Apply Security Patches: Regularly check for and apply security patches provided by VNC software vendors. Ensure that your systems are up to date with the latest security updates.
* Conduct Vulnerability Assessments: Perform regular security audits and vulnerability assessments on your VNC installations to identify and address any new or existing security issues.
* Review Logs: Regularly review VNC server logs for unusual activity or signs of attempted exploitation, and respond promptly to any suspicious events.
* Monitor and Limit Connections: Monitor the number of connections to port 5900 and implement rate limiting or connection limits to mitigate potential denial of service attacks.

##### References:

[https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2)


###### rdp MICROSOFT TERMINAL SERVICES (rdp)
*rdp  Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Critical      |         9.8    |

##### Finding Summary

CVE-2019-0708:A critical vulnerability in older versions of Windows that could allow remote code execution without authentication. Attackers could exploit this vulnerability to spread malware.

##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the rdp server which is shown below:

![rdp img](/assets/rdp.png)

##### Affected Resources:

10.10.10.11, 10.10.10.31, 10.10.10.60


##### Recommendations:

* Implement Rate Limiting: If upgrading is not immediately possible, consider implementing additional rate-limiting mechanisms at the network level to mitigate excessive login attempts.
* Monitor for Exploits: Keep an eye on security advisories and updates related to FreeRDP for any additional patches or improvements.
* Implement Monitoring and Alerts: Set up monitoring and alerting systems to detect unusual activities and potential security incidents promptly.
* Apply Security Patches: Regularly check for and apply security patches and updates for all software to mitigate vulnerabilities.
* Upgrade xrdp: Update to xrdp version 0.10.0 or later, which includes a fix for the login attempt issue.


##### References:

[https://www.cve.org/CVERecord](https://www.cve.org/CVERecord?id=CVE-2023-40576)

---


### WEB-BASED ATTACK SURFACES


The generation for the screenshots of web servers output using **Eyewitness**, the preparation of the list of HTTP and HTTPS hosts are saved up in a file. The eyewitness command to process the lists of URLs is shown below:

![eyewitness img](/assets/eyewitness1.png)

###### Eyewitness Output

![eyewitness output](/assets/eyewitness.png)
potential threats.

###### PAYLOAD GENERATION

*Web Server: Apache Tomcat(Java based)*; *Host:10.10.10.55*

The Metasploit tool,msfvenom was used to generate the payloads and filter them for the specific web server which is JAVA Based.The output is shown below:

![java img](/assets/java.png)

There was a need for the selection of a specific payload that can trigger a TCP bind shell when executed by an attacker. The output is shown below:

![java img](/assets/javapayload.png)

The resulted payload was then saved in the *payload.war*, The Java Based web server payload has an extension of **war**. The output of this process is further shown below: 

![javafile img](/assets/javafile.png)

*Web Server: Python server(base64 encode)*; *Host:10.10.10.30*

The Metasploit tool,msfvenom was used to generate the payloads and filter them for the specific web server which is Python Based.The output is shown below:

![java img](/assets/python.png)

There was a need for the selection of a specific payload that can execute a base64 encoding. The output is shown below:

![java img](/assets/pythonpayload.png)

The resulted payload was then saved in the *payload.cmd*, The Python server payload has an extension of **cmd**. The output of this process is further shown below: 

![javafile img](/assets/pythonfile.png)

---
