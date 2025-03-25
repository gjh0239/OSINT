from flask import Blueprint, request, jsonify
import requests
import os
import json
import redis
import logging
from dotenv import load_dotenv

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