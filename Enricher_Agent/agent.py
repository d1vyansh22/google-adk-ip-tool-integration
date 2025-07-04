"""
Google ADK Enricher Agent for IP Intelligence

This module contains the main ADK agent implementation that integrates multiple
threat intelligence sources (IPInfo, VirusTotal, Shodan) to analyze IP addresses
for malicious activity and provide comprehensive intelligence reports.
"""

import logging
from typing import Dict, Any, Optional
from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner

from .tools.ipinfo_tool import check_ipinfo_tool
from .tools.virustotal_tool import check_virustotal_tool
from .tools.shodan_tool import check_shodan_tool
from .tools.cache_service import create_cache_service_from_config
from .utils.ip_validator import validate_ip_address, should_analyze_ip
from .tools.abuseipdb_tool import check_abuseipdb_tool

logger = logging.getLogger(__name__)

class EnricherAgent:
    """
    Google ADK agent for comprehensive IP address intelligence and threat analysis.
    
    This agent integrates multiple threat intelligence sources to provide detailed
    analysis of IP addresses, including geolocation, threat detection, and network
    information.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Enricher Agent with configuration.

        Args:
            config: Configuration dictionary containing API keys and settings
        """
        self.config = config
        self.cache_service = create_cache_service_from_config()

        # Initialize the main ADK agent
        self.agent = self._create_agent()

        # Create session service and runner
        self.session_service = InMemorySessionService()
        self.runner = Runner(
            agent=self.agent,
            app_name=config.get('APP_NAME', 'ip-enricher-agent'),
            session_service=self.session_service
        )

        logger.info("[-] EnricherAgent initialized successfully")

    def _create_agent(self) -> Agent:
        """Create the main ADK agent with all tools configured."""
        
        # Create function tools for each service
        ipinfo_tool = FunctionTool(func=self._check_ipinfo_wrapper)
        virustotal_tool = FunctionTool(func=self._check_virustotal_wrapper)
        shodan_tool = FunctionTool(func=self._check_shodan_wrapper)
        abuseipdb_tool = FunctionTool(func=self._check_abuseipdb_wrapper)
        comprehensive_analysis_tool = FunctionTool(func=self._comprehensive_ip_analysis)
        validate_ip_tool = FunctionTool(func=self._validate_ip_wrapper)

        # Create the ADK agent
        root_agent = Agent(
            name="enricher_agent",
            model=self.config.get('MODEL', 'gemini-2.0-flash'),
            description="An AI agent specialized in IP address analysis and threat detection using multiple intelligence sources.",
            instruction="""
You are the Enricher Agent, an expert in IP address analysis and cybersecurity threat detection.
Your primary task is to analyze IP addresses to determine if they are malicious or suspicious by using multiple threat intelligence sources.

**Available Tools:**
1. validate_ip_address - Always validate IP addresses first
2. check_ipinfo - Get geolocation and network information
3. check_virustotal - Check for malicious activity reports from security vendors
4. check_shodan - Analyze open ports, services, and vulnerabilities
5. check_abuseipdb - Check for abuse reports
6. comprehensive_ip_analysis - Perform complete analysis using all sources

**Analysis Process:**
1. ALWAYS validate IP addresses first using validate_ip_address
2. For public IP addresses, use comprehensive_ip_analysis for complete intelligence
3. If specific information is requested, use individual tools as needed
4. For multiple IPs, analyze each one separately but provide a summary

**Response Guidelines:**
- Provide clear, actionable threat assessments
- Explain the reasoning behind your conclusions
- Include specific evidence from each intelligence source
- Highlight any security concerns or anomalies
- Suggest appropriate actions based on findings
- Use professional cybersecurity terminology

**Risk Assessment Criteria:**
- High Risk: Multiple malicious detections, known vulnerabilities, suspicious services
- Medium Risk: Some security concerns, unusual configurations, limited detections
- Low Risk: Clean reputation, standard configurations, no significant issues
- Unknown: Insufficient data for assessment

If multiple IP addresses are provided (comma-separated), analyze each one individually and provide both individual assessments and an overall summary.

Always provide comprehensive, evidence-based analysis with clear recommendations.
            """,
            tools=[
                validate_ip_tool,
                ipinfo_tool,
                virustotal_tool,
                shodan_tool,
                abuseipdb_tool,
                comprehensive_analysis_tool
            ]
        )

        return root_agent

    def _check_ipinfo_wrapper(self, ip_address: str) -> Dict[str, Any]:
        """Wrapper for IPInfo tool with validation."""
        if not validate_ip_address(ip_address):
            return {
                "status": "error",
                "error_message": f"Invalid IP address format: {ip_address}",
                "service": "ipinfo"
            }
        return check_ipinfo_tool(ip_address)

    def _check_virustotal_wrapper(self, ip_address: str) -> Dict[str, Any]:
        """Wrapper for VirusTotal tool with validation."""
        if not validate_ip_address(ip_address):
            return {
                "status": "error",
                "error_message": f"Invalid IP address format: {ip_address}",
                "service": "virustotal"
            }
        return check_virustotal_tool(ip_address)

    def _check_shodan_wrapper(self, ip_address: str) -> Dict[str, Any]:
        """Wrapper for Shodan tool with validation."""
        if not validate_ip_address(ip_address):
            return {
                "status": "error",
                "error_message": f"Invalid IP address format: {ip_address}",
                "service": "shodan"
            }
        return check_shodan_tool(ip_address)

    def _check_abuseipdb_wrapper(self, ip_address: str) -> Dict[str, Any]:
        """Wrapper for AbuseIPDB tool with validation."""
        if not validate_ip_address(ip_address):
            return {
                "status": "error",
                "error_message": f"Invalid IP address format: {ip_address}",
                "service": "abuseipdb"
            }
        return check_abuseipdb_tool(ip_address)

    def _validate_ip_wrapper(self, ip_address: str) -> Dict[str, Any]:
        """Wrapper for IP validation."""
        from .utils.ip_validator import get_ip_classification
        
        classification = get_ip_classification(ip_address)
        should_analyze, reason = should_analyze_ip(ip_address)
        
        return {
            "ip_address": ip_address,
            "is_valid": classification['valid'],
            "ip_type": classification.get('type', 'unknown'),
            "classification": classification.get('classification', 'unknown'),
            "should_analyze": should_analyze,
            "analysis_suitability": reason,
            "details": classification
        }

    def _comprehensive_ip_analysis(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of an IP address using all available sources.

        Args:
            ip_address: The IP address to analyze

        Returns:
            dict: Comprehensive analysis results from all sources
        """
        # Validate IP first
        if not validate_ip_address(ip_address):
            return {
                "status": "error",
                "ip_address": ip_address,
                "error_message": f"Invalid IP address format: {ip_address}"
            }

        # Check if IP should be analyzed
        should_analyze, reason = should_analyze_ip(ip_address)
        if not should_analyze:
            return {
                "status": "skipped",
                "ip_address": ip_address,
                "reason": reason,
                "recommendation": "This IP address type is not suitable for external threat intelligence analysis"
            }

        # Gather data from all sources
        logger.info(f"[-] Starting comprehensive analysis for {ip_address}")
        ipinfo_data = check_ipinfo_tool(ip_address)
        virustotal_data = check_virustotal_tool(ip_address)
        shodan_data = check_shodan_tool(ip_address)
        abuseipdb_data = check_abuseipdb_tool(ip_address)

        # Analyze and combine results
        analysis_result = self._analyze_combined_intelligence(ip_address, ipinfo_data, virustotal_data, shodan_data, abuseipdb_data)

        logger.info(f"[-] Comprehensive analysis completed for {ip_address}")
        return analysis_result

    def _analyze_combined_intelligence(self, ip_address: str, ipinfo_data: Dict,
                                     virustotal_data: Dict, shodan_data: Dict, abuseipdb_data: Dict) -> Dict[str, Any]:
        """
        Analyze and combine intelligence from all sources to provide threat assessment.

        Args:
            ip_address: The IP address being analyzed
            ipinfo_data: Data from IPInfo
            virustotal_data: Data from VirusTotal
            shodan_data: Data from Shodan
            abuseipdb_data: Data from AbuseIPDB

        Returns:
            dict: Combined analysis with threat assessment
        """
        # Calculate overall threat score (0-100)
        threat_score = 0
        threat_indicators = []

        # VirusTotal analysis
        vt_malicious = False
        if virustotal_data.get('status') == 'success':
            vt_analysis = virustotal_data.get('threat_analysis', {})
            if vt_analysis.get('is_malicious', False):
                threat_score += 40
                threat_indicators.append(f"VirusTotal: {vt_analysis.get('malicious_detections', 0)} security vendors flagged as malicious")
                vt_malicious = True
            elif vt_analysis.get('threat_score', 0) > 0:
                threat_score += min(vt_analysis.get('threat_score', 0) * 0.3, 15)
                threat_indicators.append(f"VirusTotal: Some security concerns detected")

        # Shodan analysis
        shodan_suspicious = False
        if shodan_data.get('status') == 'success':
            network_analysis = shodan_data.get('network_analysis', {})
            if network_analysis.get('is_suspicious', False):
                threat_score += 25
                threat_indicators.append(f"Shodan: Suspicious network activity detected")
                shodan_suspicious = True

            # Add points for vulnerabilities
            vuln_count = shodan_data.get('vulnerability_analysis', {}).get('vulnerability_count', 0)
            if vuln_count > 0:
                threat_score += min(vuln_count * 5, 20)
                threat_indicators.append(f"Shodan: {vuln_count} vulnerabilities detected")

            # Add points for high-risk ports
            high_risk_ports = network_analysis.get('high_risk_ports', [])
            if high_risk_ports:
                threat_score += min(len(high_risk_ports) * 3, 15)
                threat_indicators.append(f"Shodan: High-risk ports open: {high_risk_ports}")

        # IPInfo privacy concerns
        if ipinfo_data.get('status') == 'success':
            if ipinfo_data.get('has_privacy_concerns', False):
                threat_score += 10
                privacy_flags = ipinfo_data.get('privacy', {})
                active_flags = [flag for flag, active in privacy_flags.items() if active]
                if active_flags:
                    threat_indicators.append(f"IPInfo: Privacy concerns - {', '.join(active_flags)}")

        # AbuseIPDB analysis
        abuse_confidence = 0
        if abuseipdb_data.get('status') == 'success':
            abuse_confidence = abuseipdb_data.get('abuse_confidence_score', 0)
            if abuse_confidence >= 50:
                threat_score += 30
                threat_indicators.append(f"AbuseIPDB: High abuse confidence score ({abuse_confidence})")
            elif abuse_confidence > 0:
                threat_score += min(abuse_confidence * 0.2, 10)
                threat_indicators.append(f"AbuseIPDB: Some abuse reports (score {abuse_confidence})")

        # Cap threat score at 100
        threat_score = min(threat_score, 100)

        # Determine overall risk level
        if threat_score >= 70:
            risk_level = "HIGH"
            recommendation = "BLOCK - High threat indicators detected. Immediate action recommended."
        elif threat_score >= 40:
            risk_level = "MEDIUM"
            recommendation = "MONITOR - Some threat indicators detected. Additional investigation recommended."
        elif threat_score >= 10:
            risk_level = "LOW"
            recommendation = "CAUTION - Minor security concerns detected. Monitor if necessary."
        else:
            risk_level = "MINIMAL"
            recommendation = "ALLOW - No significant threat indicators detected."

        # Determine overall classification
        is_malicious = vt_malicious or shodan_suspicious or threat_score >= 50

        return {
            "status": "success",
            "ip_address": ip_address,
            "overall_assessment": {
                "is_malicious": is_malicious,
                "threat_score": threat_score,
                "risk_level": risk_level,
                "recommendation": recommendation,
                "threat_indicators": threat_indicators
            },
            "intelligence_sources": {
                "ipinfo": ipinfo_data,
                "virustotal": virustotal_data,
                "shodan": shodan_data,
                "abuseipdb": abuseipdb_data
            },
            "summary": self._generate_analysis_summary(ip_address, threat_score, risk_level,
                                                     ipinfo_data, virustotal_data, shodan_data, abuseipdb_data),
            "analysis_timestamp": self._get_timestamp()
        }

    def _generate_analysis_summary(self, ip: str, threat_score: float, risk_level: str,
                                 ipinfo_data: Dict, virustotal_data: Dict, shodan_data: Dict, abuseipdb_data: Dict) -> str:
        """Generate a human-readable summary of the analysis."""
        # Location from IPInfo
        location = "Unknown location"
        if ipinfo_data.get('status') == 'success':
            loc_data = ipinfo_data.get('location', {})
            if loc_data.get('city') and loc_data.get('country'):
                location = f"{loc_data['city']}, {loc_data['country']}"
            elif loc_data.get('country'):
                location = loc_data['country']

        summary = f"IP {ip} is located in {location} with a {risk_level} risk level (threat score: {threat_score}/100). "

        # VirusTotal summary
        if virustotal_data.get('status') == 'success':
            threat_analysis = virustotal_data.get('threat_analysis', {})
            malicious_count = threat_analysis.get('malicious_detections', 0)
            total_engines = threat_analysis.get('total_engines', 0)
            if total_engines > 0:
                summary += f"VirusTotal analysis: {malicious_count}/{total_engines} security vendors flagged this IP. "

        # Shodan summary
        if shodan_data.get('status') == 'success':
            network_analysis = shodan_data.get('network_analysis', {})
            port_count = network_analysis.get('port_count', 0)
            vuln_count = shodan_data.get('vulnerability_analysis', {}).get('vulnerability_count', 0)
            summary += f"Shodan analysis: {port_count} open ports detected"
            if vuln_count > 0:
                summary += f", {vuln_count} vulnerabilities found"
            summary += ". "

        # AbuseIPDB summary
        if abuseipdb_data.get('status') == 'success':
            abuse_score = abuseipdb_data.get('abuse_confidence_score', 0)
            total_reports = abuseipdb_data.get('total_reports', 0)
            if abuse_score > 0:
                summary += f"AbuseIPDB: Abuse confidence score {abuse_score} with {total_reports} reports. "

        return summary

    def _get_timestamp(self) -> str:
        """Get current timestamp for analysis."""
        import datetime
        return datetime.datetime.now().isoformat()

    def get_cache_metrics(self) -> Dict[str, Any]:
        """Get cache performance metrics."""
        if self.cache_service.is_available():
            return {
                "cache_available": True,
                "cache_metrics": self.cache_service.get_metrics(),
                "cache_health": self.cache_service.get_health_info()
            }
        else:
            return {
                "cache_available": False,
                "message": "Redis cache not available"
            }

    def clear_cache(self, service_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Clear the Redis cache.

        Args:
            service_name: (Currently ignored) Reserved for future filtering.

        Returns:
            Dictionary with the result of the cache clear operation.
        """
        try:
            if not self.cache_service or not self.cache_service.is_available():
                return {
                    "success": False,
                    "message": "Redis cache service is not available."
                }

            # Access the raw Redis client and call FLUSHDB
            redis_client = getattr(self.cache_service, "redis_client", None)
            if redis_client is None:
                raise AttributeError("Redis client not exposed by cache service.")
            
            redis_client.flushdb()
            return {
                "success": True,
                "message": "Redis cache successfully cleared.",
                "service": service_name or "all"
            }

        except AttributeError:
            return {
                "success": False,
                "message": "Redis client not accessible."
            }
        except Exception as e:
            logger.error(f"[x] Error during Redis cache clear: {e}")
            return {
                "success": False,
                "message": f"Error clearing Redis cache: {str(e)}"
            }