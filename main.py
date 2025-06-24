"""
Main Entry Point for Google ADK IP Enricher Agent

This module provides the main entry point for running the IP enricher agent
in various modes (interactive, CLI, web UI) while maintaining compatibility
with the existing CLI tool patterns.
"""

import asyncio
import sys
import argparse
import logging
from typing import List, Optional
from config import Config, setup_logging, validate_configuration
from Enricher_Agent.agent import EnricherAgent

logger = logging.getLogger(__name__)

def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Google ADK IP Enricher Agent - Comprehensive IP Intelligence Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive ADK agent mode
  python main.py

  # Analyze single IP address
  python main.py --ip 8.8.8.8

  # Analyze multiple IP addresses
  python main.py --ip "8.8.8.8,1.1.1.1,208.67.222.222"

  # Batch analysis from file
  python main.py --batch ips.txt

  # Check configuration status
  python main.py --config-check

  # Clear cache
  python main.py --clear-cache

  # Run with ADK web UI
  python main.py --web

  # Monitor cache and API metrics
  python main.py --monitor

For interactive mode with advanced features:
  adk web --agent main:enricher_agent

Environment Variables:
  Set API keys and configuration in .env file or environment variables.
  See .env.template for reference.
        """
    )
    
    # Core functionality arguments
    parser.add_argument(
        '--ip',
        help='IP address(es) to analyze (single IP or comma-separated list)'
    )
    
    parser.add_argument(
        '--batch',
        help='File containing IP addresses to analyze (one per line)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['text', 'json', 'csv'],
        default='text',
        help='Output format (default: text)'
    )
    
    # Configuration and management
    parser.add_argument(
        '--config-check',
        action='store_true',
        help='Check configuration status and exit'
    )
    
    parser.add_argument(
        '--clear-cache',
        nargs='?',
        const='all',
        help='Clear cache entries (specify service: ipinfo, virustotal, shodan, or all)'
    )
    
    parser.add_argument(
        '--monitor',
        action='store_true',
        help='Show monitoring info (cache metrics, API stats) and exit'
    )
    
    # ADK specific options
    parser.add_argument(
        '--web',
        action='store_true',
        help='Launch ADK web interface'
    )
    
    parser.add_argument(
        '--user-id',
        default='default_user',
        help='User ID for session management'
    )
    
    # Development and debugging
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable Redis caching for this run'
    )
    
    return parser


async def run_ip_analysis(agent: EnricherAgent, ip_addresses: str, 
                         user_id: str, output_format: str) -> None:
    """Run IP analysis and display results."""
    try:
        logger.info(f"🔍 Starting IP analysis for: {ip_addresses}")
        
        # Perform analysis
        results = await agent.analyze_ips_async(ip_addresses, user_id)
        
        # Display results based on format
        if output_format == 'json':
            import json
            print(json.dumps(results, indent=2))
        elif output_format == 'csv':
            _output_csv_format(results)
        else:
            _output_text_format(results)
            
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)


def _output_text_format(results: List[dict]) -> None:
    """Output results in human-readable text format."""
    print("\n" + "=" * 80)
    print("🛡️  IP ENRICHER AGENT - ANALYSIS RESULTS")
    print("=" * 80)
    
    for i, result in enumerate(results, 1):
        ip = result.get('ip_address', 'Unknown')
        status = result.get('status', 'Unknown')
        
        print(f"\n📍 Analysis {i}: {ip}")
        print("-" * 40)
        
        if status == 'success':
            if 'agent_analysis' in result:
                print(result['agent_analysis'])
            else:
                print("✅ Analysis completed successfully")
        elif status == 'error':
            error_msg = result.get('error_message', 'Unknown error')
            print(f"❌ Error: {error_msg}")
        else:
            print(f"⚠️  Status: {status}")
        
        if 'timestamp' in result:
            print(f"⏰ Analyzed at: {result['timestamp']}")
    
    print("\n" + "=" * 80)


def _output_csv_format(results: List[dict]) -> None:
    """Output results in CSV format."""
    import csv
    import sys
    
    writer = csv.writer(sys.stdout)
    
    # CSV header
    writer.writerow(['IP Address', 'Status', 'Analysis Summary', 'Timestamp'])
    
    # CSV rows
    for result in results:
        ip = result.get('ip_address', '')
        status = result.get('status', '')
        analysis = result.get('agent_analysis', result.get('error_message', ''))
        timestamp = result.get('timestamp', '')
        
        # Clean analysis text for CSV
        if analysis:
            analysis = analysis.replace('\n', ' ').replace('\r', ' ')[:500]
        
        writer.writerow([ip, status, analysis, timestamp])


async def run_batch_analysis(agent: EnricherAgent, batch_file: str, 
                           user_id: str, output_format: str) -> None:
    """Run batch analysis from file."""
    try:
        # Read IP addresses from file
        with open(batch_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        if not ips:
            print(f"❌ No valid IP addresses found in {batch_file}")
            return
        
        logger.info(f"📋 Processing {len(ips)} IP addresses from {batch_file}")
        
        # Convert to comma-separated string for processing
        ip_string = ','.join(ips)
        await run_ip_analysis(agent, ip_string, user_id, output_format)
        
    except FileNotFoundError:
        print(f"❌ File not found: {batch_file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Batch analysis failed: {e}")
        print(f"❌ Error reading batch file: {e}")
        sys.exit(1)


def run_config_check() -> None:
    """Check and display configuration status."""
    Config.print_config_status()
    
    validation = Config.validate_config()
    if not validation['valid']:
        print("❌ Configuration validation failed. Please fix the errors above.")
        sys.exit(1)
    else:
        print("✅ Configuration is valid and ready for use.")


def run_cache_management(agent: EnricherAgent, service: str) -> None:
    """Handle cache management operations."""
    try:
        if service == 'all':
            result = agent.clear_cache()
        else:
            result = agent.clear_cache(service_name=service)
        
        if result['success']:
            print(f"✅ Cache cleared: {result['deleted_entries']} entries removed for {result['service']}")
        else:
            print(f"❌ Cache clear failed: {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        logger.error(f"❌ Cache management failed: {e}")
        print(f"❌ Error: {e}")


def run_monitoring(agent: EnricherAgent) -> None:
    """Display monitoring information."""
    print("\n" + "=" * 60)
    print("📊 IP ENRICHER AGENT - MONITORING INFO")
    print("=" * 60)
    
    try:
        # Cache metrics
        cache_info = agent.get_cache_metrics()
        
        if cache_info['cache_available']:
            metrics = cache_info['cache_metrics']
            health = cache_info['cache_health']
            
            print(f"\n💾 Redis Cache Status: {health.get('status', 'unknown').upper()}")
            print(f"   Hit Rate: {metrics['hit_rate_percent']}%")
            print(f"   Total Requests: {metrics['total_requests']}")
            print(f"   Cache Hits: {metrics['hits']}")
            print(f"   Cache Misses: {metrics['misses']}")
            print(f"   Cache Failures: {metrics['failures']}")
            print(f"   Store Operations: {metrics['stores']}")
            
            if 'redis_info' in health:
                redis_info = health['redis_info']
                print(f"\n🔧 Redis Server Info:")
                print(f"   Version: {redis_info.get('redis_version', 'unknown')}")
                print(f"   Connected Clients: {redis_info.get('connected_clients', 'unknown')}")
                print(f"   Memory Usage: {redis_info.get('used_memory_human', 'unknown')}")
        else:
            print("\n💾 Redis Cache Status: UNAVAILABLE")
            print(f"   Message: {cache_info.get('message', 'Cache not available')}")
        
        # Configuration summary
        print(f"\n⚙️  Configuration:")
        print(f"   Model: {Config.MODEL}")
        print(f"   API Timeout: {Config.API_TIMEOUT}s")
        print(f"   Max Retries: {Config.MAX_RETRIES}")
        print(f"   IPInfo: {'✅' if Config.IPINFO_API_KEY else '❌'}")
        print(f"   VirusTotal: {'✅' if Config.VIRUSTOTAL_API_KEY else '❌'}")
        print(f"   Shodan: {'✅' if Config.SHODAN_API_KEY else '❌'}")
        
    except Exception as e:
        logger.error(f"❌ Monitoring failed: {e}")
        print(f"❌ Error retrieving monitoring info: {e}")
    
    print("=" * 60 + "\n")


def launch_adk_web() -> None:
    """Launch ADK web interface."""
    print("🌐 Launching ADK Web Interface...")
    print("   Use the following command to start the web UI:")
    print("   adk web --agent main:enricher_agent")
    print("\n   Or run interactively with:")
    print("   python -c \"from main import get_enricher_agent; agent = get_enricher_agent(); from google.adk.runners import Runner; runner = Runner(agent); runner.run()\"")


async def run_interactive_mode(agent: EnricherAgent) -> None:
    """Run the agent in interactive CLI mode."""
    print("\n🛡️  IP ENRICHER AGENT - INTERACTIVE MODE")
    print("=" * 50)
    print("Enter IP addresses to analyze (comma-separated for multiple)")
    print("Commands: 'quit', 'exit', 'q' to exit, 'help' for help")
    print("         'config' to show configuration, 'monitor' to show metrics")
    
    if Config.IPINFO_API_KEY:
        print("✅ IPInfo API configured")
    if Config.VIRUSTOTAL_API_KEY:
        print("✅ VirusTotal API configured")
    if Config.SHODAN_API_KEY:
        print("✅ Shodan API configured")
    
    print("\n" + "=" * 50)
    
    while True:
        try:
            user_input = input("\n🔍 Enter IP address(es): ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q', '']:
                print("\n👋 Goodbye!")
                break
            elif user_input.lower() == 'help':
                print("\n📚 Available commands:")
                print("   • Enter IP address(es) to analyze")
                print("   • 'config' - Show configuration status")
                print("   • 'monitor' - Show cache and API metrics")
                print("   • 'clear-cache' - Clear all cached data")
                print("   • 'quit' or 'exit' - Exit the program")
                continue
            elif user_input.lower() == 'config':
                run_config_check()
                continue
            elif user_input.lower() == 'monitor':
                run_monitoring(agent)
                continue
            elif user_input.lower() == 'clear-cache':
                run_cache_management(agent, 'all')
                continue
            
            # Analyze IP addresses
            await run_ip_analysis(agent, user_input, "interactive_user", "text")
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted by user. Goodbye!")
            break
        except Exception as e:
            logger.error(f"❌ Interactive mode error: {e}")
            print(f"\n❌ Error: {e}")


def get_enricher_agent() -> EnricherAgent:
    """Get configured enricher agent instance."""
    return EnricherAgent(Config.to_dict())


async def main() -> None:
    """Main entry point."""
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    if args.debug:
        Config.LOG_LEVEL = 'DEBUG'
    setup_logging()
    
    # Configuration check
    if args.config_check:
        run_config_check()
        return
    
    # Validate configuration before proceeding
    if not validate_configuration():
        print("❌ Configuration validation failed. Use --config-check for details.")
        sys.exit(1)
    
    # Initialize agent
    try:
        agent = EnricherAgent(Config.to_dict())
    except Exception as e:
        logger.error(f"❌ Failed to initialize agent: {e}")
        print(f"❌ Agent initialization failed: {e}")
        sys.exit(1)
    
    # Handle monitoring
    if args.monitor:
        run_monitoring(agent)
        return
    
    # Handle cache management
    if args.clear_cache is not None:
        run_cache_management(agent, args.clear_cache)
        return
    
    # Handle web UI launch
    if args.web:
        launch_adk_web()
        return
    
    # Handle IP analysis
    if args.ip:
        await run_ip_analysis(agent, args.ip, args.user_id, args.output_format)
        return
    
    # Handle batch analysis
    if args.batch:
        await run_batch_analysis(agent, args.batch, args.user_id, args.output_format)
        return
    
    # Interactive mode
    await run_interactive_mode(agent)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        print(f"❌ Application error: {e}")
        sys.exit(1)