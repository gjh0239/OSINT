from flask import Blueprint, request, jsonify
import requests
import os
from dotenv import load_dotenv

main_bp = Blueprint('main', __name__)

load_dotenv()

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
    
    # Get LeakCheck API key from environment variable
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
            
        return jsonify({
            "breached": data.get('found', 0) > 0,
            "found": data.get('found', 0),
            "exposed_data": data.get('fields', []),
            "breaches": data.get('sources', [])
        })
            
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
    
    # Get Shodan API key from environment variable
    api_key = os.getenv('SHODAN_API_KEY', '')
    if not api_key:
        return jsonify({"error": "Shodan API key not configured on server"}), 500
    
    # Determine if query is IP address or hostname
    endpoint = ""
    if query.replace('.', '').isdigit():  # Simple check for IP format
        # Looking up specific IP
        endpoint = f"https://api.shodan.io/shodan/host/{query}"
    else:
        # Domain search
        endpoint = "https://api.shodan.io/shodan/host/search"
    
    try:
        # Make request to Shodan API
        params = {"key": api_key}
        if endpoint.endswith("search"):
            params["query"] = f"hostname:{query}"
            
        response = requests.get(endpoint, params=params)
        response.raise_for_status()
        return jsonify(response.json())
            
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
    
    # Get VirusTotal API key from environment variable
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
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500