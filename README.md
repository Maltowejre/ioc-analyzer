# IOC Analyzer

A web-based threat intelligence tool that analyzes **Indicators of Compromise (IOCs)** such as IP addresses, domains, URLs, and file hashes using multiple threat intelligence sources.

The tool aggregates results from several platforms and provides a unified **Threat Score** and **Final Verdict**.


## Live Demo

You can try the tool directly in your browser:

https://ioc-analyzer.streamlit.app/

No installation required.

Simply enter an IOC (IP, domain, URL, or hash) and click **Analyze**.


## Features

- Analyze multiple IOC types:
  - IP Address
  - Domain
  - URL
  - File Hash
- Multi-source threat intelligence
- Automatic IOC type detection
- Threat scoring system
- Final verdict classification
- Clean web interface


## Threat Intelligence Sources

The analyzer uses the following sources:

- **AbuseIPDB** – IP abuse reports and confidence scores
- **AlienVault OTX** – threat intelligence pulses and reputation
- **VirusTotal** – malware and reputation analysis

### Source usage by IOC type

| IOC Type | AbuseIPDB | OTX | VirusTotal |
|----------|-----------|-----|------------|
| IP       | Yes       | Yes | Yes |
| Domain   | No        | Yes | Yes |
| URL      | No        | Yes | Yes |
| Hash     | No        | Yes | Yes |

