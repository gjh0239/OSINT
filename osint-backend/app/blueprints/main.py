from flask import Blueprint, request, jsonify
import os
import re
import logging
from dotenv import load_dotenv
import redis
from app.blueprints.GET_API import (
    VirusTotalAPI, ShodanAPI, LeakCheckAPI, 
    URLScanAPI, AbuseIPDBAPI, DNSService, WHOISService
)

main_bp = Blueprint('main', __name__)

# Load environment variables
load_dotenv()

#TODO: Postgres migration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0') # TODO: Replace default with production URL

# Configure Logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Redis 
#TODO: WILL MIGRATE TO POSTGRES LATER
redis_client = redis.StrictRedis.from_url(REDIS_URL) # Strictredis does not provide backwards compatibility - use redis.Redis instead

# Initialize API classes
virus_total_api = VirusTotalAPI()
shodan_api = ShodanAPI()
leak_check_api = LeakCheckAPI()
url_scan_api = URLScanAPI()
abuse_ipdb_api = AbuseIPDBAPI()
dns_service = DNSService()
whois_service = WHOISService()

def detect_input_type(value):
    """Detect if the input is an IP, email or domain"""
    # IP address pattern
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    # Email pattern
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    # Domain pattern (simple version)
    domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$')
    
    if ip_pattern.match(value):
        return "ip"
    elif email_pattern.match(value):
        return "email"
    elif domain_pattern.match(value):
        return "domain"
    return None

def ip_lookup(value, api_usage, errors):
    
    vt_result = None
    shodan_result = None
    abuseipdb_result = None
    
    try:
        vt_result = virus_total_api.lookup_query(value)
        api_usage['virustotal_ip'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"VirusTotal error: {str(e)}")
    
    try:
        shodan_result = shodan_api.lookup_query(value)
        api_usage['shodan'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"Shodan error: {str(e)}")
        
    try:
        abuseipdb_result = abuse_ipdb_api.lookup_query(value)
        api_usage['abuseipdb'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"AbuseIPDB error: {str(e)}")
    
    results = {
        'type': 'ip',
        'virustotal': vt_result,
        'shodan': shodan_result,
        'abuseipdb': abuseipdb_result
    }
        
    return results

def email_lookup(value, api_usage, errors):
    
    leakcheck_result = None
    vt_result = None
    
    try:
        leakcheck_result = leak_check_api.lookup_query(value)
        api_usage['leakcheck'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"LeakCheck error: {str(e)}")
        
    try:
        vt_result = virus_total_api.lookup_query(value)
        api_usage['virustotal_email'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"VirusTotal error: {str(e)}")
        
    results = {
        'type': 'email',
        'leakcheck': leakcheck_result,
        'virustotal': vt_result
    }
    
    return results

def domain_lookup(value, api_usage, errors):
    
    urlscan_result = None
    whois_result = None
    dns_result = None
    vt_result = None
    shodan_result = None
    
    try:
        urlscan_result = url_scan_api.lookup_query(value)
        api_usage['urlscan'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"URLScan error: {str(e)}")
        
    try:
        whois_result = whois_service.get_whois_info(value)
        api_usage['whois'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"Whois error: {str(e)}")
    
    try:
        dns_result = dns_service.get_dns_records(value)
        api_usage['dns'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"DNS error: {str(e)}")
        
    try:
        vt_result = virus_total_api.lookup_query(value)
        api_usage['virustotal_domain'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"VirusTotal error: {str(e)}")
        
    try:
        shodan_result = shodan_api.lookup_query(value)
        api_usage['shodan'] += 1
        api_usage['total_calls'] += 1
    except Exception as e:
        errors.append(f"Shodan error: {str(e)}")
    
    results = {
        'type': 'domain',
        'urlscan': urlscan_result,
        'whois': whois_result,
        'dns': dns_result,
        'virustotal': vt_result,
        'shodan': shodan_result
    }
    
    return results

@main_bp.route('/unified-search', methods=['POST'])
def unified_search():
    """
    Unified search endpoint that detects input type and processes accordingly.
    Handles single or multiple comma-separated values.
    ---
    tags:
      - Unified Search API
    parameters:
      - name: query
        in: body
        required: true
        schema:
          type: object
          properties:
            query:
              type: string
              description: IP address, email, domain, or comma-separated list
              example: "8.8.8.8,1.1.1.1"
    responses:
      200:
        description: Unified search results
      400:
        description: Missing or invalid query
      500:
        description: Server error
    """
    data = request.json
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({"error": "No search query provided"}), 400
    
    # Parse comma-separated values (with or without spaces)
    # Strip http/https prefixes and split by commas
    cleaned_query = re.sub(r'^https?://', '', query)
    values = [re.sub(r'^https?://', '', val.strip()) for val in re.split(r',\s*', cleaned_query) if val.strip()]
    
    # Results dictionary
    results = {}
    api_usage = {       #TODO: Add new APIs here for frontend to track
        "virustotal_ip": 0,
        "virustotal_domain": 0,
        "virustotal_email": 0,
        "shodan": 0,
        "leakcheck": 0,
        "abuseipdb": 0,
        "whois": 0,
        "dns": 0,
        "urlscan": 0,
        "total_calls": 0
    }
    
    errors = []
    
    for value in values:
        
        # Detect input type
        input_type = detect_input_type(value)
        
        if not input_type:
            errors.append(f"Could not determine type for: {value}")
            continue
        
        #Process the value based on the determined type
        if input_type == "ip":
            results[value] = ip_lookup(value, api_usage, errors)
        elif input_type == "email":
            results[value] = email_lookup(value, api_usage, errors)
        elif input_type == "domain":
            results[value] = domain_lookup(value, api_usage, errors)
    
    # Prepare final response
    response = {
        'results': results,
        'api_usage': api_usage,
        'errors': errors,
        'query_count': len(values),
        'success_count': len(results),        
    }
    
    return jsonify(response)