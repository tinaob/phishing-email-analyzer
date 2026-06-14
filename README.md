# Phishing Email Analyzer 🔍

A Python-based cybersecurity tool that analyzes suspicious email files (.eml) 
to detect phishing indicators automatically.

---

## What Problem Does This Solve?

Phishing emails are one of the most common attack vectors in cybersecurity. 
This tool helps security analysts quickly identify phishing indicators in 
email files without manually reading through raw email headers.

---

## What It Detects

- **Sender spoofing** — flags when the Reply-To address differs from the From address
- **Suspicious URLs** — extracts all URLs from the email body automatically
- **Malicious links** — checks every URL against the VirusTotal database (40+ security engines)
- **Domain impersonation** — surface-level detection of fake sender domains

---

## Example Output

---

## Tools and Technologies Used

| Tool | Purpose |
|---|---|
| Python 3 | Core programming language |
| Python `email` library | Parsing .eml email files |
| Python `re` library | Extracting URLs using regex |
| Python `requests` library | Calling the VirusTotal API |
| VirusTotal API | Scanning URLs against 40+ security engines |

---

## How to Run It Yourself

### 1. Clone this repository

### 2. Install required libraries

### 3. Add your VirusTotal API key
Sign up free at virustotal.com, get your API key, and paste it into 
the analyzer.py file on this line:

### 4. Add your .eml file to the folder
Save any email as a .eml file and place it in the project folder.
Update this line in analyzer.py with your filename:

### 5. Run the tool

---

## What I Learned Building This

- How to parse raw email headers and identify spoofing techniques
- How phishing emails use Reply-To mismatches to deceive victims
- How to integrate a real security API (VirusTotal) into a Python script
- How private IP addresses in email links indicate internal phishing attempts
- Why automated tools still require human analysis for full accuracy

---

## Limitations and Future Improvements

- Currently analyzes one email at a time — future version will scan entire folders
- VirusTotal free API has rate limits — paid tier would allow bulk scanning
- Does not yet detect HTML-based URL hiding (URLs disguised behind anchor text)
- Future version will add a visual HTML report output

---

## Author

**Clementina Obasi**  
Cybersecurity Analyst | CySA+ | CCNA CyberOps | Google Cybersecurity Certified  
[LinkedIn](https://www.linkedin.com/in/clementina-obasi-b89a3381/)

---

*Built as part of my cybersecurity portfolio — June 2026*
