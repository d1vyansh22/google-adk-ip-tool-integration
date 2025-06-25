# Google ADK IP Tool Integration

## Overview

This project implements an agent-tool framework for comprehensive IP address intelligence and threat analysis, designed to be part of a larger multi-agentic cybersecurity system. It takes natural language input from the user, processes it using an LLM, and leverages an Enricher Agent with tools that integrate IPInfo, VirusTotal, and Shodan APIs. The system generates detailed reports on whether an IP address is malicious, supporting investigations into cybersecurity attacks and exposing vulnerabilities using security logs (e.g., from MS Sentinel SIEM).

## Features

- **Natural Language Input**: Accepts user queries in plain English, processed by an LLM.
- **Multi-Source IP Intelligence**: Integrates IPInfo, VirusTotal, and Shodan APIs for comprehensive IP analysis.
- **Malicious IP Detection**: Aggregates threat intelligence to determine if an IP is malicious.
- **Detailed Reporting**: Generates human-readable reports summarizing risk, threat scores, and findings.
- **Security Log Analysis**: Designed to work with logs from SIEM systems (e.g., MS Sentinel) for attack chain investigation.
- **Redis Caching**: Caches results for performance and rate-limiting protection.
- **Multiple Modes**: Supports CLI, batch, interactive, and web UI operation.
- **Configurable**: All settings and API keys are managed via environment variables.
- **Extensible Framework**: Built as part of a multi-agentic system, ready for further tool and agent integration.

## Project Structure

```
google-adk-ip-tool-integration/
├── Enricher_Agent/
│   ├── __init__.py
│   ├── agent.py
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── cache_service.py
│   │   ├── ipinfo_tool.py
│   │   ├── shodan_tool.py
│   │   └── virustotal_tool.py
│   └── utils/
│       ├── __init__.py
│       └── ip_validator.py
├── config.py
├── main.py
├── requirements.txt
├── MIGRATION_GUIDE.md
└── README.md
```

## Setup & Running Locally

### Prerequisites
- Python 3.8+
- [pip](https://pip.pypa.io/en/stable/)
- API keys for IPInfo, VirusTotal, and Shodan (free/community keys are sufficient for testing)
- Redis server (local or remote)

### 1. Clone the Repository
```bash
git clone <repo-url>
cd google-adk-ip-tool-integration
```

### 2. Set Up Environment Variables
Create a `.env` file in the project root with the following keys:
```
IPINFO_API_KEY=your_ipinfo_key
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
API_TIMEOUT=10
MAX_RETRIES=3
CACHE_TTL=86400
ADK_MODEL=gemini-2.0-flash
APP_NAME=ip-enricher-agent
LOG_LEVEL=INFO
```
(See `config.py` for all available options.)

### 3. Install Dependencies
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Run the Application

#### Interactive Agent Mode
```bash
python main.py
```

#### Analyze a Single IP
```bash
python main.py --ip 8.8.8.8
```

#### Analyze Multiple IPs
```bash
python main.py --ip "8.8.8.8,1.1.1.1,208.67.222.222"
```

#### Batch Analysis from File
```bash
python main.py --batch ips.txt
```

#### Check Configuration
```bash
python main.py --config-check
```

#### Clear Cache
```bash
python main.py --clear-cache
```

#### Monitor Cache and API Metrics
```bash
python main.py --monitor
```

#### Launch Web UI (if ADK web is installed)
```bash
adk web --agent main:enricher_agent
```

### Output Formats
- Default: text
- JSON: `--output-format json`
- CSV: `--output-format csv`

## Example Usage

- **Interactive:**
  - Enter IPs, use commands like `config`, `monitor`, `clear-cache`, or `help`.
- **Batch:**
  - Provide a file with one IP per line.
- **Web UI:**
  - Use the ADK web interface for a graphical experience.

## Improvements & Roadmap

Planned for future versions:
- **Deeper SIEM Integration:** Direct ingestion and parsing of logs from MS Sentinel and other SIEMs.
- **More Threat Sources:** Integration with additional threat intelligence APIs.
- **Automated Attack Chain Analysis:** End-to-end investigation and visualization of attack paths.
- **Advanced Reporting:** PDF/HTML export, alerting, and dashboard features.
- **User Management:** Multi-user support and session tracking.
- **Cloud Deployment:** Docker and cloud-native deployment guides.
- **Enhanced LLM Capabilities:** More advanced natural language understanding and hypothesis testing.

## License
MIT License (see LICENSE file)

## Credits
- Developed by Divyansh Gupta
- Built with Google ADK, IPInfo, VirusTotal, Shodan, and open-source technologies
