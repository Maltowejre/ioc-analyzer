# IOC Analyzer

Threat Intelligence CLI tool that analyzes **Indicators of Compromise (IOCs)** using multiple security intelligence sources and provides a unified threat score and verdict.

The tool aggregates data from different threat intelligence platforms to help analysts quickly evaluate suspicious indicators.


## Features

- Multi-source threat intelligence lookup
- Supports multiple IOC types
- Unified threat scoring system
- Clean CLI output using **Rich**
- Modular architecture (sources, scoring, formatter)
- Easy to extend with new intelligence sources


## Supported IOC Types

| IOC Type | Sources Used |
|--------|--------|
| IP Address | AbuseIPDB, OTX, VirusTotal |
| Domain | OTX, VirusTotal |
| URL | OTX, VirusTotal |
| File Hash | OTX, VirusTotal |


## Intelligence Sources

The analyzer currently integrates with:

- **AbuseIPDB**
- **AlienVault OTX**
- **VirusTotal**

These sources provide reputation data, abuse reports, and malware detections.
