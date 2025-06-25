# Google ADK IP Intelligence Agent

## A Powerful IP Threat Analysis Agent Built on Google's Agent Development Kit




The Google ADK IP Intelligence Agent is a sophisticated agent-based system that leverages Google's Agent Development Kit (ADK) to provide comprehensive IP address intelligence and threat analysis. It seamlessly integrates multiple leading threat intelligence sources (IPInfo, VirusTotal, and Shodan) into a unified platform, enabling detailed security assessments, risk scoring, and actionable recommendations.

This project demonstrates how to build effective security intelligence agents using Google's ADK architecture, combining modular design, powerful caching, and advanced analysis capabilities.

## Key Features

### ADK Agent Capabilities

- **Built on Google's Agent Development Kit**: Leverages Google's framework for building intelligent, conversational agents with tool-based architecture
- **Conversational AI**: Interact with the agent in a natural, conversational manner to analyze IP addresses
- **Multi-Tool Integration**: Uses ADK's `FunctionTool` paradigm to integrate multiple intelligence sources
- **Session Management**: Maintains context and state across interactions for advanced analysis patterns
- **ADK Web Interface**: Browser-based UI for easy, non-technical user access
- **Streaming Results**: Real-time analysis and progressive results display

### IP Intelligence Features

- **Multi-Source Intelligence**: Integrates three powerful threat intelligence platforms:
  - **IPInfo**: Geolocation, ASN, organization, and privacy detection (VPN/proxy/Tor)
  - **VirusTotal**: Reputation checks against dozens of security vendors
  - **Shodan**: Port scanning, service enumeration, and vulnerability detection
- **Comprehensive Analysis**:
  - **Threat Scoring**: Calculates overall risk (0-100 scale) based on combined intelligence
  - **Risk Classification**: Categorizes IPs as HIGH, MEDIUM, LOW, or MINIMAL risk
  - **Evidence Collection**: Provides detailed indicators supporting the risk assessment
- **Performance Optimization**:
  - **Redis Caching**: Improves response times and reduces API quota usage
  - **Health Monitoring**: Tracks cache performance metrics
  - **Exponential Backoff**: Robust retry logic for API resilience
- **Advanced IP Validation**:
  - **Multiple Formats**: Validates both IPv4 and IPv6 addresses
  - **Classification**: Identifies public, private, loopback, and reserved IPs
  - **Filtering**: Prevents unnecessary API calls for non-public addresses

## System Architecture

The project follows a modular agent-based architecture built on Google's ADK framework:

### Core Components

1. **EnricherAgent (`agent.py`)**:
   - Central ADK agent that orchestrates the entire analysis process
   - Manages tool invocation, data synthesis, and response generation
   - Provides comprehensive IP analysis combining all intelligence sources

2. **Function Tools (`tools/`)**:
   - Each external API is wrapped in a dedicated `FunctionTool` for ADK
   - Modular design for easy maintenance and extension
   - Includes logic for API calls, response parsing, and caching

3. **Cache Service (`cache_service.py`)**:
   - Redis-based caching layer for all API tools
   - Configurable TTL and metrics tracking
   - Improves performance and respects API rate limits

4. **IP Validation (`utils/ip_validator.py`)**:
   - Comprehensive validation for IPv4 and IPv6 formats
   - Classifies IPs by type (public, private, reserved, etc.)
   - Prevents unnecessary API calls for non-analyzable IPs

### Analysis Workflow

The standard workflow follows this pattern:

1. User provides IP address(es) for analysis
2. Agent validates and classifies the IP(s)
3. For valid public IPs, agent concurrently queries all intelligence sources
4. Data from all sources is combined and analyzed
5. Risk assessment and scoring is performed
6. Final report with evidence and recommendations is generated

## Prerequisites

Before installing the system, ensure you have the following:

- Python 3.8+ installed
- Redis server (optional but recommended for performance)
- API keys for the following services:
  - [IPInfo](https://ipinfo.io/)
  - [VirusTotal](https://www.virustotal.com/)
  - [Shodan](https://www.shodan.io/)
- Google ADK access

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/d1vyansh22/google-adk-ip-tool-integration.git
cd google-adk-ip-tool-integration
```

### 2. Set Up a Virtual Environment

```bash
# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# For Windows
.venv\Scripts\activate
# For macOS/Linux
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```env
# API Keys
IPINFO_API_KEY=your_ipinfo_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
CACHE_TTL=86400

# ADK Configuration
ADK_MODEL=gemini-2.0-flash
APP_NAME=ip-enricher-agent

# API Settings
API_TIMEOUT=10
MAX_RETRIES=3
LOG_LEVEL=INFO
```

## Usage

### ADK Web Interface (Recommended)

For an interactive web interface, use the ADK web command:

```bash
adk web --agent main:enricher_agent
```

This launches a web interface (typically at http://127.0.0.1:8080) where you can:
- Enter IP addresses for analysis
- See detailed intelligence from all sources
- Interact with the agent in a conversational manner
- View the agent's reasoning and analysis process

### Programmatic Usage

You can also use the agent programmatically in your Python code:

```python
from main import enricher_agent_instance

# Access the underlying agent
agent = enricher_agent_instance.agent

# For direct function tool usage
from Enricher_Agent.tools.ipinfo_tool import check_ipinfo_tool
result = check_ipinfo_tool("8.8.8.8")
print(result)
```

### Natural Language Queries

The agent accepts natural language queries such as:

- "Analyze IP address 8.8.8.8 for potential threats"
- "Is 203.0.113.42 malicious? Provide detailed analysis"
- "Check the reputation and security status of 1.1.1.1"
- "Perform comprehensive analysis of 192.0.2.150"

## Development and Deployment

### Local Development

For local development and testing:

1. Set up the environment as described in the Installation section
2. Make changes to the code
3. Test the agent using the ADK web interface

### Deployment Options

The agent can be deployed in various environments:

#### Google Cloud Run

1. Build a container:
   ```bash
   gcloud builds submit --tag gcr.io/your-project/ip-enricher-agent
   ```

2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy ip-enricher-agent \
     --image gcr.io/your-project/ip-enricher-agent \
     --platform managed
   ```

#### Vertex AI Agent Engine

For seamless integration with Google's AI platform:

1. Package the agent for Vertex AI
2. Deploy through the Google Cloud Console or CLI
3. Integrate with other Google Cloud services

#### Docker Container

```bash
# Build the Docker image
docker build -t ip-enricher-agent .

# Run the container
docker run -p 8080:8080 ip-enricher-agent
```

## Advanced Features

### Custom Risk Scoring

The agent uses a sophisticated algorithm to calculate risk scores based on multiple factors:

- **VirusTotal**: Malicious detection counts, vendor reputation
- **Shodan**: Vulnerabilities, suspicious services, high-risk ports
- **IPInfo**: Privacy concerns (VPN, Tor, proxy usage)

These factors are weighted and combined to produce an overall threat score (0-100).

### Cache Management

The Redis cache significantly improves performance by storing API responses:

- **TTL Control**: Configure how long data is cached
- **Service-Specific Caching**: Each service has independent caching
- **Metrics**: Track cache hits, misses, and performance

### Agent Capabilities

The ADK agent provides sophisticated analysis capabilities:

- **Context Awareness**: Maintains conversation context for follow-up questions
- **Multi-IP Analysis**: Can analyze multiple IP addresses in a single conversation
- **Explanation Generation**: Provides detailed reasoning for its assessments
- **Adaptive Responses**: Adjusts detail level based on user needs

## Troubleshooting

### API Key Issues

- Ensure all API keys are correctly set in the `.env` file
- Check that you have sufficient quota and permissions for each service
- Verify API key validity with each provider directly

### Redis Connection

- Ensure Redis server is running
- Check connection settings in `.env`
- Use `redis-cli ping` to verify connectivity

### Rate Limiting

- API services may enforce rate limits
- The system implements exponential backoff but may still be affected
- Consider increasing `MAX_RETRIES` or implementing additional throttling

## License

MIT License

## Credits

- Developed by Divyansh Gupta
- Built with Google ADK, IPInfo, VirusTotal, Shodan, and open-source technologies

*This project is not officially endorsed by Google, IPInfo, VirusTotal, or Shodan.*