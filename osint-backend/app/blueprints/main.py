from flask import Blueprint, request, jsonify
import requests
import os
import json
import redis
import logging
from dotenv import load_dotenv
import re

main_bp = Blueprint('main', __name__)

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Redis setup
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
redis_client = redis.from_url(REDIS_URL)

# Cache TTL values (in seconds)
CACHE_TTL = {
    'default': 3600,  # 1 hour
    'email_breach': 86400,  # 24 hours
    'ip_lookup': 3600,  # 1 hour
    'domain_lookup': 7200,  # 2 hours
    'email_lookup': 86400,  # 24 hours
}

def get_from_cache(cache_key):
    """Retrieve data from Redis cache"""
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            logger.info(f"Cache hit for key: {cache_key}")
            return json.loads(cached_data)
        logger.info(f"Cache miss for key: {cache_key}")
    except Exception as e:
        logger.error(f"Error retrieving from Redis cache: {str(e)}")
    return None

def set_in_cache(cache_key, data, ttl=CACHE_TTL['default']):
    """Store data in Redis cache with TTL"""
    try:
        redis_client.setex(
            cache_key,
            ttl,
            json.dumps(data)
        )
        logger.info(f"Stored data in cache with key: {cache_key}, TTL: {ttl}s")
    except Exception as e:
        logger.error(f"Failed to store data in Redis cache: {str(e)}")

@main_bp.route('/query', methods=['GET'])
def query_api():
    user_input = request.args.get('input', '')
    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    # Example API call
    try:
        response = requests.get(f"https://api.example.com/search?q={user_input}")
        response.raise_for_status()  # Raise an error for failed requests
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# Add the index route from modules/main/route.py
@main_bp.route('/', methods=['GET'])
def index():
    """ Example endpoint with simple greeting.
    ---
    tags:
      - Example API
    responses:
      200:
        description: A simple greeting
        schema:
          type: object
          properties:
            data:
              type: object
              properties:
                message:
                  type: string
                  example: "Hello World!"
    """
    return jsonify(data={'message': 'Hello, World!'})

# Leakcheck email breach check
@main_bp.route('/check-email', methods=['POST'])
def check_email_breach():
    """
    Check if an email has been involved in data breaches using LeakCheck.io API.
    ---
    tags:
      - Email Security API
    parameters:
      - name: email
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Email address to check
              example: "user@example.com"
    responses:
      200:
        description: Email breach check results
        schema:
          type: object
          properties:
            breached:
              type: boolean
            found:
              type: integer
            exposed_data:
              type: array
              items:
                type: string
            breaches:
              type: array
              items:
                type: object
      400:
        description: Missing or invalid email
      500:
        description: Server error
    """
    data = request.json
    email = data.get('email', '')
    
    if not email:
        return jsonify({"error": "No email provided"}), 400
    
    # Check cache first
    cache_key = f"leakcheck:email:{email}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    # Not in cache, get LeakCheck API key from environment variable
    api_key = os.getenv('LEAKCHECK_API_KEY', '')
    if not api_key:
        return jsonify({"error": "LeakCheck API key not configured on server"}), 500
    
    # LeakCheck.io API call
    try:
        response = requests.get(f"https://leakcheck.io/api/public?key={api_key}&check={email}")
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('success'):
            return jsonify({"error": data.get('message', 'Unknown error from API')}), 500
            
        result = {
            "breached": data.get('found', 0) > 0,
            "found": data.get('found', 0),
            "exposed_data": data.get('fields', []),
            "breaches": data.get('sources', [])
        }
        
        # Store in cache
        set_in_cache(cache_key, result, CACHE_TTL['email_breach'])
        
        return jsonify(result)
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# shodan lookup
@main_bp.route('/shodan-lookup', methods=['POST'])
def shodan_lookup():
    """
    Look up information about an IP address or domain using Shodan API.
    ---
    tags:
      - Shodan API
    parameters:
      - name: query
        in: body
        required: true
        schema:
          type: object
          properties:
            query:
              type: string
              description: IP address or domain to look up
              example: "8.8.8.8"
    responses:
      200:
        description: Shodan lookup results
      400:
        description: Missing or invalid query
      500:
        description: Server error
    """
    data = request.json
    query = data.get('query', '')
    
    if not query:
        return jsonify({"error": "No IP address or domain provided"}), 400
    
    # Check cache first
    query_type = "ip" if query.replace('.', '').isdigit() else "domain"
    cache_key = f"shodan:{query_type}:{query}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    # Not in cache, get Shodan API key
    api_key = os.getenv('SHODAN_API_KEY', '')
    if not api_key:
        return jsonify({"error": "Shodan API key not configured on server"}), 500
    
    # Determine if query is IP address or hostname
    try:
        # Make request to Shodan API
        if query_type == "ip":
            # Looking up specific IP
            response = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={api_key}")
        else:
            # Domain search
            response = requests.get(
                "https://api.shodan.io/shodan/host/search", 
                params={"key": api_key, "query": f"hostname:{query}"}
            )
            
        response.raise_for_status()
        result = response.json()
        
        # Store in cache
        ttl = CACHE_TTL['ip_lookup'] if query_type == "ip" else CACHE_TTL['domain_lookup']
        set_in_cache(cache_key, result, ttl)
        
        return jsonify(result)
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/virustotal-lookup', methods=['POST'])
def virustotal_lookup():
    """
    Performs a lookup against the VirusTotal API for a given IP address.
    ---
    tags:
      - VirusTotal API
    parameters:
      - name: ip
        in: body
        required: true
        schema:
          type: object
          properties:
            ip:
              type: string
              description: IP address to look up
              example: "8.8.8.8"
    responses:
      200:
        description: VirusTotal IP address analysis results
      400:
        description: Missing or invalid IP address
      500:
        description: Server error or API request failed
    """
    data = request.json
    ip_address = data.get('ip', '')
    
    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400
    
    # Check cache first
    cache_key = f"virustotal:ip:{ip_address}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    # Not in cache, get VirusTotal API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return jsonify({"error": "VirusTotal API key not configured on server"}), 500
    
    # Make request to VirusTotal API
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", 
            headers=headers
        )
        response.raise_for_status()
        result = response.json()
        
        # Store in cache
        set_in_cache(cache_key, result, CACHE_TTL['ip_lookup'])
        
        return jsonify(result)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/virustotal-domain-lookup', methods=['POST'])
def virustotal_domain_lookup():
    """
    Performs a lookup against the VirusTotal API for a given domain.
    ---
    tags:
      - VirusTotal API
    parameters:
      - name: domain
        in: body
        required: true
        schema:
          type: object
          properties:
            domain:
              type: string
              description: Domain name to look up
              example: "example.com"
    responses:
      200:
        description: VirusTotal domain analysis results
      400:
        description: Missing or invalid domain
      500:
        description: Server error or API request failed
    """
    data = request.json
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    # Check cache first
    cache_key = f"virustotal:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    # Not in cache, get VirusTotal API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return jsonify({"error": "VirusTotal API key not configured on server"}), 500
    
    # Make request to VirusTotal API
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}", 
            headers=headers
        )
        response.raise_for_status()
        result = response.json()
        
        # Store in cache
        set_in_cache(cache_key, result, CACHE_TTL['domain_lookup'])
        
        return jsonify(result)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/virustotal-email-lookup', methods=['POST'])
def virustotal_email_lookup():
    """
    Performs a lookup against the VirusTotal API for a given email address.
    ---
    tags:
      - VirusTotal API
    parameters:
      - name: email
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Email address to look up
              example: "user@example.com"
    responses:
      200:
        description: VirusTotal email analysis results
      400:
        description: Missing or invalid email address
      500:
        description: Server error or API request failed
    """
    data = request.json
    email = data.get('email', '')
    
    if not email:
        return jsonify({"error": "No email address provided"}), 400
    
    # Check cache first
    cache_key = f"virustotal:email:{email}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    # Not in cache, get VirusTotal API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return jsonify({"error": "VirusTotal API key not configured on server"}), 500
    
    # Make request to VirusTotal API using the search endpoint
    try:
        headers = {"x-apikey": api_key}
        response = requests.get(
            "https://www.virustotal.com/api/v3/search",
            params={"query": email}, 
            headers=headers
        )
        response.raise_for_status()
        result = response.json()
        
        # Store in cache
        set_in_cache(cache_key, result, CACHE_TTL['email_lookup'])
        
        return jsonify(result)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

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
    values = [val.strip() for val in re.split(r',\s*', query) if val.strip()]
    
    # Prepare result containers
    results = {}
    api_usage = {
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
    
    # Process each value
    for value in values:
        # Detect type
        input_type = detect_input_type(value)
        
        if not input_type:
            errors.append(f"Could not determine type for: {value}")
            continue
        
        # Process based on detected type
        try:
            if input_type == "ip":
                # For IPs, query multiple services
                vt_result = process_virustotal_ip(value)
                shodan_result = process_shodan_query(value)
                abuseipdb_result = process_abuseipdb(value)
                
                results[value] = {
                    "type": "ip",
                    "virustotal": vt_result,
                    "shodan": shodan_result,
                    "abuseipdb": abuseipdb_result
                }
                
                api_usage["virustotal_ip"] += 1
                api_usage["shodan"] += 1
                api_usage["abuseipdb"] += 1
                api_usage["total_calls"] += 3
                
            elif input_type == "email":
                # For emails, query LeakCheck
                leakcheck_result = process_email_breach(value)
                
                results[value] = {
                    "type": "email",
                    "leakcheck": leakcheck_result
                }
                
                api_usage["leakcheck"] += 1
                api_usage["total_calls"] += 1
                
            elif input_type == "domain":
                # For domains, query multiple services
                vt_result = process_virustotal_domain(value)
                shodan_result = process_shodan_query(value)
                whois_result = process_whois(value)
                dns_result = process_dns(value)
                urlscan_result = process_urlscan(value)
                
                results[value] = {
                    "type": "domain",
                    "virustotal": vt_result,
                    "shodan": shodan_result,
                    "whois": whois_result,
                    "dns": dns_result,
                    "urlscan": urlscan_result
                }
                
                api_usage["virustotal_domain"] += 1
                api_usage["shodan"] += 1
                api_usage["whois"] += 1
                api_usage["dns"] += 1
                api_usage["urlscan"] += 1
                api_usage["total_calls"] += 5
        
        except Exception as e:
            errors.append(f"Error processing {value}: {str(e)}")
    
    # Prepare final response
    response = {
        "results": results,
        "api_usage": api_usage,
        "errors": errors,
        "query_count": len(values),
        "success_count": len(results)
    }
    
    return jsonify(response)

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

def process_virustotal_ip(ip):
    """Process a VirusTotal IP lookup without making a full HTTP request"""
    # Check cache first
    cache_key = f"virustotal:ip:{ip}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    # Not in cache, get VirusTotal API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        raise Exception("VirusTotal API key not configured on server")
    
    # Make request to VirusTotal API
    headers = {"x-apikey": api_key}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
        headers=headers
    )
    response.raise_for_status()
    result = response.json()
    
    # Store in cache
    set_in_cache(cache_key, result, CACHE_TTL['ip_lookup'])
    
    return result

def process_virustotal_domain(domain):
    """Process a VirusTotal domain lookup without making a full HTTP request"""
    # Check cache first
    cache_key = f"virustotal:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    # Not in cache, get VirusTotal API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        raise Exception("VirusTotal API key not configured on server")
    
    # Make request to VirusTotal API
    headers = {"x-apikey": api_key}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}", 
        headers=headers
    )
    response.raise_for_status()
    result = response.json()
    
    # Store in cache
    set_in_cache(cache_key, result, CACHE_TTL['domain_lookup'])
    
    return result

def process_shodan_query(query):
    """Process a Shodan lookup without making a full HTTP request"""
    # Check cache first
    query_type = "ip" if query.replace('.', '').isdigit() else "domain"
    cache_key = f"shodan:{query_type}:{query}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    # Not in cache, get Shodan API key
    api_key = os.getenv('SHODAN_API_KEY', '')
    if not api_key:
        raise Exception("Shodan API key not configured on server")
    
    # Make request to Shodan API
    if query_type == "ip":
        # Looking up specific IP
        response = requests.get(f"https://api.shodan.io/shodan/host/{query}?key={api_key}")
    else:
        # Domain search
        response = requests.get(
            "https://api.shodan.io/shodan/host/search", 
            params={"key": api_key, "query": f"hostname:{query}"}
        )
        
    response.raise_for_status()
    result = response.json()
    
    # Store in cache
    ttl = CACHE_TTL['ip_lookup'] if query_type == "ip" else CACHE_TTL['domain_lookup']
    set_in_cache(cache_key, result, ttl)
    
    return result

def process_email_breach(email):
    """Process an email breach check without making a full HTTP request"""
    # Check cache first
    cache_key = f"leakcheck:email:{email}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    # Not in cache, get LeakCheck API key
    api_key = os.getenv('LEAKCHECK_API_KEY', '')
    if not api_key:
        raise Exception("LeakCheck API key not configured on server")
    
    # Make LeakCheck API call
    response = requests.get(f"https://leakcheck.io/api/public?key={api_key}&check={email}")
    response.raise_for_status()
    
    data = response.json()
    
    if not data.get('success'):
        raise Exception(data.get('message', 'Unknown error from API'))
        
    result = {
        "breached": data.get('found', 0) > 0,
        "found": data.get('found', 0),
        "exposed_data": data.get('fields', []),
        "breaches": data.get('sources', [])
    }
    
    # Store in cache
    set_in_cache(cache_key, result, CACHE_TTL['email_breach'])
    
    return result

@main_bp.route('/urlscan-lookup', methods=['POST'])
def urlscan_lookup():
    """
    Look up information about a URL/domain using urlscan.io API.
    ---
    tags:
      - Domain Security API
    parameters:
      - name: domain
        in: body
        required: true
        schema:
          type: object
          properties:
            domain:
              type: string
              description: Domain to scan
              example: "example.com"
    responses:
      200:
        description: URLScan.io scan results
      400:
        description: Missing or invalid domain
      500:
        description: Server error
    """
    data = request.json
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    cache_key = f"urlscan:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    api_key = os.getenv('URLSCAN_API_KEY', '')
    if not api_key:
        return jsonify({"error": "urlscan.io API key not configured"}), 500
    
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    scan_data = {"url": domain, "visibility": "public"}
    
    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=scan_data
        )
        response.raise_for_status()
        
        scan_result = response.json()
        set_in_cache(cache_key, scan_result, CACHE_TTL['domain_lookup'])
        
        return jsonify(scan_result)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/whois-lookup', methods=['POST'])
def whois_lookup():
    """
    Look up WHOIS data for a domain.
    ---
    tags:
      - Domain Security API
    parameters:
      - name: domain
        in: body
        required: true
        schema:
          type: object
          properties:
            domain:
              type: string
              description: Domain to lookup
              example: "example.com"
    responses:
      200:
        description: WHOIS lookup results
      400:
        description: Missing or invalid domain
      500:
        description: Server error
    """
    data = request.json
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    cache_key = f"whois:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    try:
        import whois
        result = whois.whois(domain)
        
        # Convert complex objects to strings for JSON serialization
        whois_data = {
            "domain_name": result.domain_name,
            "registrar": result.registrar,
            "creation_date": str(result.creation_date),
            "expiration_date": str(result.expiration_date),
            "updated_date": str(result.updated_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "emails": result.emails,
            "registrant": result.registrant,
            "admin": result.admin,
            "tech": result.tech,
            "raw": result.text
        }
        
        set_in_cache(cache_key, whois_data, CACHE_TTL['domain_lookup'])
        return jsonify(whois_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/dns-lookup', methods=['POST'])
def dns_lookup():
    """
    Look up DNS records for a domain.
    ---
    tags:
      - Domain Security API
    parameters:
      - name: domain
        in: body
        required: true
        schema:
          type: object
          properties:
            domain:
              type: string
              description: Domain to lookup
              example: "example.com"
    responses:
      200:
        description: DNS records lookup results
      400:
        description: Missing or invalid domain
      500:
        description: Server error
    """
    data = request.json
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({"error": "No domain provided"}), 400
    
    cache_key = f"dns:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    try:
        import dns.resolver
        result = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = [str(answer) for answer in answers]
            except dns.resolver.NoAnswer:
                result[record_type] = []
            except Exception as e:
                result[record_type] = [f"Error: {str(e)}"]
        
        set_in_cache(cache_key, result, CACHE_TTL['domain_lookup'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/abuseipdb-lookup', methods=['POST'])
def abuseipdb_lookup():
    """
    Look up IP reputation using AbuseIPDB.
    ---
    tags:
      - IP Security API
    parameters:
      - name: ip
        in: body
        required: true
        schema:
          type: object
          properties:
            ip:
              type: string
              description: IP address to check
              example: "8.8.8.8"
    responses:
      200:
        description: AbuseIPDB lookup results
      400:
        description: Missing or invalid IP address
      500:
        description: Server error
    """
    data = request.json
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({"error": "No IP address provided"}), 400
    
    cache_key = f"abuseipdb:ip:{ip}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return jsonify(cached_result)
    
    api_key = os.getenv('ABUSEIPDB_API_KEY', '')
    if not api_key:
        return jsonify({"error": "AbuseIPDB API key not configured"}), 500
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params
        )
        response.raise_for_status()
        
        result = response.json()
        set_in_cache(cache_key, result, CACHE_TTL['ip_lookup'])
        
        return jsonify(result)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# Helper functions for unified search
def process_urlscan(domain):
    """Process a URLScan.io lookup"""
    cache_key = f"urlscan:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    api_key = os.getenv('URLSCAN_API_KEY', '')
    if not api_key:
        raise Exception("URLScan API key not configured on server")
    
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    scan_data = {"url": domain, "visibility": "public"}
    
    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        json=scan_data
    )
    response.raise_for_status()
    
    result = response.json()
    set_in_cache(cache_key, result, CACHE_TTL['domain_lookup'])
    
    return result

def process_whois(domain):
    """Process a WHOIS lookup"""
    cache_key = f"whois:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    try:
        import whois
        result = whois.whois(domain)
        
        # Convert complex objects to strings for JSON serialization
        whois_data = {
            "domain_name": result.domain_name,
            "registrar": result.registrar,
            "creation_date": str(result.creation_date),
            "expiration_date": str(result.expiration_date),
            "updated_date": str(result.updated_date),
            "name_servers": result.name_servers,
            "status": result.status,
            "emails": result.emails,
            "registrant": result.registrant,
            "admin": result.admin,
            "tech": result.tech,
            "raw": result.text
        }
        
        set_in_cache(cache_key, whois_data, CACHE_TTL['domain_lookup'])
        return whois_data
    except Exception as e:
        logger.error(f"WHOIS error: {str(e)}")
        return {"error": str(e)}

def process_dns(domain):
    """Process a DNS lookup"""
    cache_key = f"dns:domain:{domain}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    try:
        import dns.resolver
        result = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = [str(answer) for answer in answers]
            except dns.resolver.NoAnswer:
                result[record_type] = []
            except Exception as e:
                result[record_type] = [f"Error: {str(e)}"]
        
        set_in_cache(cache_key, result, CACHE_TTL['domain_lookup'])
        return result
    except Exception as e:
        logger.error(f"DNS lookup error: {str(e)}")
        return {"error": str(e)}

def process_abuseipdb(ip):
    """Process an AbuseIPDB lookup"""
    cache_key = f"abuseipdb:ip:{ip}"
    cached_result = get_from_cache(cache_key)
    if cached_result:
        return cached_result
    
    api_key = os.getenv('ABUSEIPDB_API_KEY', '')
    if not api_key:
        raise Exception("AbuseIPDB API key not configured on server")
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    response = requests.get(
        'https://api.abuseipdb.com/api/v2/check',
        headers=headers,
        params=params
    )
    response.raise_for_status()
    
    result = response.json()
    set_in_cache(cache_key, result, CACHE_TTL['ip_lookup'])
    
    return result