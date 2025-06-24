# Migration Guide: CLI Tool → Google ADK Agent

## Step-by-Step Migration Process

### Step 1: Project Structure Setup

**From your existing CLI project, create the new ADK structure:**

```bash
# Create the new project directory structure
mkdir -p google-adk-ip-tool-integration/multi_tool_agent/{tools,utils}

# Copy the migration files into place
cp -r /path/to/updated/files/* google-adk-ip-tool-integration/
```

**New Project Structure:**
```
google-adk-ip-tool-integration/
├── multi_tool_agent/
│   ├── __init__.py
│   ├── enricher_agent.py           # NEW: Main ADK agent
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── cache_service.py        # UPDATED: Enhanced from original
│   │   ├── ipinfo_tool.py          # UPDATED: ADK tool wrapper
│   │   ├── virustotal_tool.py      # NEW: VirusTotal integration
│   │   └── shodan_tool.py          # NEW: Shodan integration
│   └── utils/
│       ├── __init__.py
│       └── ip_validator.py         # UPDATED: Enhanced validation
├── config.py                       # UPDATED: Enhanced configuration
├── main.py                         # UPDATED: ADK integration
├── requirements.txt                # UPDATED: ADK dependencies
├── .env.template                   # NEW: Environment template
└── README.md                       # UPDATED: Documentation
```

### Step 2: Environment Configuration

**1. Copy and update environment variables:**

```bash
# Copy the template
cp .env.template .env

# Add your existing API keys
nano .env
```

**2. Add new API keys for expanded functionality:**
- **VirusTotal API Key**: [Get here](https://www.virustotal.com/gui/join-us)
- **Shodan API Key**: [Get here](https://account.shodan.io/register)

**3. Migrate existing Redis configuration:**
Your existing Redis setup should work without changes. The new system uses the same cache key patterns.

### Step 3: Install Dependencies

**Update your Python environment:**

```bash
# Activate your virtual environment
source ip-tool-env/bin/activate  # Or your existing env

# Install new dependencies
pip install -r requirements.txt

# Verify ADK installation
python -c "import google.adk; print('ADK installed successfully')"
```

### Step 4: Data Migration

**Your existing cached data is compatible:**
- Cache keys follow the same pattern: `{service}:{ip_address}`
- Data structures are backward compatible
- TTL settings remain the same

**Optional: Clear cache for fresh start:**
```bash
python main.py --clear-cache
```

### Step 5: Validate Configuration

**Check that everything is properly configured:**

```bash
# Validate configuration
python main.py --config-check

# Test Redis connection
python -c "
from multi_tool_agent.tools.cache_service import create_cache_service_from_config
cache = create_cache_service_from_config()
print('Redis status:', cache.get_health_info())
"
```

### Step 6: Test Basic Functionality

**1. Test CLI compatibility:**
```bash
# These commands should work exactly like before
python main.py --ip 8.8.8.8
python main.py --batch ips.txt
python main.py --monitor
```

**2. Test new ADK features:**
```bash
# Interactive agent mode
python main.py

# Web UI (new feature)
adk web --agent main:enricher_agent
```

### Step 7: Feature Comparison

| Feature | Original CLI Tool | New ADK Agent | Migration Notes |
|---------|------------------|---------------|-----------------|
| Single IP lookup | ✅ `python ip_lookup_enhanced.py 8.8.8.8` | ✅ `python main.py --ip 8.8.8.8` | Same functionality |
| Batch processing | ✅ `--batch file.txt` | ✅ `--batch file.txt` | Enhanced error handling |
| Interactive mode | ✅ Built-in | ✅ Enhanced with ADK | Better conversational interface |
| Redis caching | ✅ Basic | ✅ Enhanced | Improved metrics and health checks |
| IPInfo API | ✅ Full support | ✅ Enhanced | Better error handling |
| VirusTotal API | ❌ Not supported | ✅ **NEW** | Malware detection |
| Shodan API | ❌ Not supported | ✅ **NEW** | Vulnerability scanning |
| Web interface | ❌ CLI only | ✅ **NEW** | ADK web UI |
| Agent interactions | ❌ Not supported | ✅ **NEW** | Conversational AI |
| Multi-source analysis | ❌ Single source | ✅ **NEW** | Combined intelligence |

### Step 8: Advanced Migration Steps

**1. Custom Modifications Migration:**

If you have custom modifications in your original `ip_lookup_enhanced.py`, you can integrate them:

```python
# In multi_tool_agent/tools/ipinfo_tool.py
# Add your custom logic to the get_ipinfo_data function

def get_ipinfo_data(ip_address: str, **kwargs) -> Dict[str, Any]:
    # Your existing custom logic here
    # The new structure preserves all original functionality
    pass
```

**2. Configuration Migration:**

Your existing configuration patterns are preserved:

```python
# Old: Direct environment variables
API_KEY = os.getenv('IPINFO_API_KEY')

# New: Centralized config (backward compatible)
from config import Config
api_key = Config.IPINFO_API_KEY
```

**3. Logging Migration:**

Enhanced logging with same familiar patterns:

```python
# Old: Basic logging
import logging
logging.basicConfig(level=logging.INFO)

# New: Enhanced logging (auto-configured)
from config import setup_logging
setup_logging()  # Uses your LOG_LEVEL setting
```

### Step 9: Testing Migration

**Run comprehensive tests:**

```bash
# Test original functionality
python main.py --ip 8.8.8.8 --output-format json
python main.py --batch test_ips.txt

# Test new features
python main.py --ip 8.8.8.8  # Should show multi-source analysis
python main.py  # Interactive mode

# Test error handling
python main.py --ip "invalid.ip"
python main.py --ip "192.168.1.1"  # Private IP handling
```

### Step 10: Deployment Migration

**For existing deployments:**

1. **Docker Migration:**
```dockerfile
# Update your Dockerfile to use new requirements.txt
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

2. **Systemd Service Migration:**
```ini
# Update your service file
[Unit]
Description=IP Enricher Agent
After=network.target redis.service

[Service]
Type=simple
User=ip-enricher
WorkingDirectory=/opt/ip-enricher-agent
ExecStart=/opt/ip-enricher-agent/adk-env/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Step 11: Rollback Plan

**If you need to rollback:**

1. **Keep your original code:**
```bash
# Backup original before migration
cp -r ip-validation-v1.0 ip-validation-v1.0-backup
```

2. **The new system maintains compatibility:**
   - Same Redis cache structure
   - Same API key variables
   - Same basic CLI interface

3. **Switch back if needed:**
```bash
# Use original tool
cd ip-validation-v1.0-backup
python ip_lookup_enhanced.py 8.8.8.8

# Use new tool with old interface
cd google-adk-ip-tool-integration
python main.py --ip 8.8.8.8
```

## Migration Checklist ✅

- [ ] **Step 1**: Project structure created
- [ ] **Step 2**: Environment configured (.env file)
- [ ] **Step 3**: Dependencies installed (Google ADK)
- [ ] **Step 4**: Redis cache compatible
- [ ] **Step 5**: Configuration validated
- [ ] **Step 6**: Basic functionality tested
- [ ] **Step 7**: Feature comparison reviewed
- [ ] **Step 8**: Custom modifications migrated
- [ ] **Step 9**: Comprehensive testing completed
- [ ] **Step 10**: Deployment updated
- [ ] **Step 11**: Rollback plan prepared

## Post-Migration Benefits

**Enhanced Capabilities:**
- 🔍 **Multi-source intelligence** (IPInfo + VirusTotal + Shodan)
- 🤖 **Conversational AI interface** with Google ADK
- 🌐 **Web-based interface** for non-technical users
- 📊 **Advanced threat scoring** and risk assessment
- ⚡ **Better performance** with enhanced caching
- 🛡️ **Comprehensive security analysis**

**Maintained Compatibility:**
- ✅ All original CLI commands work
- ✅ Same cache storage format
- ✅ Same configuration variables
- ✅ Same output formats available
- ✅ Same Redis setup

## Troubleshooting Migration Issues

**Common Issues and Solutions:**

1. **Import Errors:**
```bash
# Ensure virtual environment is activated
source adk-env/bin/activate
pip install -r requirements.txt
```

2. **Configuration Issues:**
```bash
# Check configuration
python main.py --config-check
```

3. **Redis Connection:**
```bash
# Test Redis
redis-cli ping
# Should return PONG
```

4. **API Key Issues:**
```bash
# Verify API keys in .env
grep -E "(IPINFO|VIRUSTOTAL|SHODAN)_API_KEY" .env
```

**Need Help?**
- Review the README.md for detailed setup instructions
- Check configuration with `python main.py --config-check`
- Enable debug logging with `python main.py --debug`
- Test individual components with `python main.py --monitor`

---

**Migration Complete! 🎉**

Your CLI tool is now a sophisticated ADK agent with enhanced capabilities while maintaining full backward compatibility.